import type { OAuthTokens, QuotaCache } from '../types/index';

const DRIVE_API = 'https://www.googleapis.com/drive/v3';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

export interface GDriveFile {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  parents?: string[];
  trashed?: boolean;
  thumbnailLink?: string;
  webViewLink?: string;
  webContentLink?: string;
  createdTime: string;
  modifiedTime: string;
  md5Checksum?: string;
}

export interface GDriveFolder {
  id: string;
  name: string;
  parents?: string[];
}

export class GoogleDriveError extends Error {
  constructor(public status: number, message: string, public data?: any) {
    super(message);
    this.name = 'GoogleDriveError';
  }
}

export class GoogleDriveService {
  private encryptionKey?: string;

  constructor(
    private kv: KVNamespace,
    private clientId: string,
    private clientSecret: string,
    encryptionKey?: string
  ) {
    this.encryptionKey = encryptionKey;
  }

  // ─── Token Management ───

  async getValidToken(driveAccountId: string): Promise<string> {
    // Try tokens: prefix first (new), fallback to oauth: (legacy)
    const raw = await this.kv.get(`tokens:${driveAccountId}`) ?? await this.kv.get(`oauth:${driveAccountId}`);
    if (!raw) {
      throw new Error(`No tokens found for drive ${driveAccountId}`);
    }

    let tokensJson = raw;
    if (this.encryptionKey) {
      try {
        const { decryptOrPassthrough } = await import('../lib/crypto');
        tokensJson = await decryptOrPassthrough(raw, this.encryptionKey);
      } catch {
        // Fallback to raw if decrypt fails
      }
    }

    const tokens = JSON.parse(tokensJson);

    // Return cached token if not expired (with 60s buffer)
    if (tokens.expiresAt > Date.now() + 60_000) {
      return tokens.accessToken;
    }

    // Service account: re-sign JWT using stored credentials
    if (tokens.saCredentials) {
      return this.refreshServiceAccountToken(driveAccountId, tokens.saCredentials);
    }

    // OAuth: use refresh token
    return this.refreshToken(driveAccountId, tokens.refreshToken);
  }

  private async refreshServiceAccountToken(driveAccountId: string, saCredentialsJson: string): Promise<string> {
    const saKey = JSON.parse(saCredentialsJson);
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = {
      iss: saKey.client_email,
      scope: 'https://www.googleapis.com/auth/drive',
      aud: saKey.token_uri || 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    };

    const toBase64Url = (obj: unknown) =>
      btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const unsignedToken = `${toBase64Url(header)}.${toBase64Url(payload)}`;

    const pemContents = saKey.private_key
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\n/g, '');
    const binaryDer = Uint8Array.from(atob(pemContents), (c: string) => c.charCodeAt(0));

    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      new TextEncoder().encode(unsignedToken)
    );

    const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const jwt = `${unsignedToken}.${signature}`;

    const tokenRes = await fetch(saKey.token_uri || 'https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
      }),
    });

    if (!tokenRes.ok) {
      throw new Error(`Service account token refresh failed: ${await tokenRes.text()}`);
    }

    const data: { access_token: string; expires_in: number } = await tokenRes.json();

    // Update KV with new access token
    const newTokens = JSON.stringify({
      accessToken: data.access_token,
      refreshToken: '',
      expiresAt: Date.now() + data.expires_in * 1000,
      saCredentials: saCredentialsJson,
    });

    if (this.encryptionKey) {
      const { encrypt } = await import('../lib/crypto');
      const encrypted = await encrypt(newTokens, this.encryptionKey);
      await this.kv.put(`tokens:${driveAccountId}`, encrypted);
    } else {
      await this.kv.put(`tokens:${driveAccountId}`, newTokens);
    }

    return data.access_token;
  }

  private async refreshToken(driveAccountId: string, refreshToken: string): Promise<string> {
    const response = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token refresh failed for ${driveAccountId}: ${error}`);
    }

    const data: { access_token: string; expires_in: number } = await response.json();

    // Update KV with new access token (keep existing refresh token)
    const newTokens = JSON.stringify({
      accessToken: data.access_token,
      refreshToken,
      expiresAt: Date.now() + data.expires_in * 1000,
    } satisfies OAuthTokens);

    if (this.encryptionKey) {
      const { encrypt } = await import('../lib/crypto');
      const encrypted = await encrypt(newTokens, this.encryptionKey);
      await this.kv.put(`tokens:${driveAccountId}`, encrypted);
    } else {
      await this.kv.put(`oauth:${driveAccountId}`, newTokens);
    }

    return data.access_token;
  }

  // ─── Quota ───

  async getQuota(
    driveAccountId: string
  ): Promise<{ total: number; used: number }> {
    // Check KV cache first
    const cached = await this.kv.get(`quota:${driveAccountId}`);
    if (cached) {
      const quota: QuotaCache = JSON.parse(cached);
      return { total: quota.total, used: quota.used };
    }

    // Fetch from Google Drive API
    const token = await this.getValidToken(driveAccountId);
    const response = await fetch(`${DRIVE_API}/about?fields=storageQuota`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch quota: ${await response.text()}`);
    }

    const data: {
      storageQuota: { limit?: string; usage?: string };
    } = await response.json();

    const total = parseInt(data.storageQuota.limit ?? '0', 10);
    const used = parseInt(data.storageQuota.usage ?? '0', 10);

    // Cache in KV (5-min TTL)
    await this.kv.put(
      `quota:${driveAccountId}`,
      JSON.stringify({ total, used, updatedAt: new Date().toISOString() } satisfies QuotaCache),
      { expirationTtl: 300 }
    );

    return { total, used };
  }

  // ─── Folder Operations ───

  async getRootFolderId(driveAccountId: string): Promise<string> {
    const token = await this.getValidToken(driveAccountId);
    const response = await fetch(`${DRIVE_API}/files/root?fields=id`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      throw new Error(`Failed to get root folder ID: ${await response.text()}`);
    }
    const data: { id: string } = await response.json();
    return data.id;
  }

  async createFolder(
    driveAccountId: string,
    name: string,
    parentId?: string
  ): Promise<string> {
    const token = await this.getValidToken(driveAccountId);

    const metadata: Record<string, unknown> = {
      name,
      mimeType: 'application/vnd.google-apps.folder',
    };
    if (parentId) {
      metadata.parents = [parentId];
    }

    const response = await fetch(`${DRIVE_API}/files`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(metadata),
    });

    if (!response.ok) {
      throw new Error(`Failed to create folder: ${await response.text()}`);
    }

    const folder: { id: string } = await response.json();
    return folder.id;
  }

  // ─── Upload ───

  async initiateResumableUpload(
    driveAccountId: string,
    fileName: string,
    mimeType: string,
    parentFolderId: string
  ): Promise<string> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(
      `https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'X-Upload-Content-Type': mimeType,
        },
        body: JSON.stringify({
          name: fileName,
          parents: [parentFolderId],
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to initiate upload: ${await response.text()}`);
    }

    const uploadUrl = response.headers.get('Location');
    if (!uploadUrl) {
      throw new Error('No upload URL in response');
    }

    return uploadUrl;
  }

  // ─── File Operations ───

  async getFile(
    driveAccountId: string,
    googleFileId: string
  ): Promise<GDriveFile> {
    const token = await this.getValidToken(driveAccountId);
    const fields = 'id,name,mimeType,size,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum';

    const response = await fetch(`${DRIVE_API}/files/${googleFileId}?fields=${fields}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to get file: ${await response.text()}`);
    }

    return response.json();
  }

  async downloadFile(driveAccountId: string, googleFileId: string, mimeType?: string): Promise<{stream: ReadableStream<Uint8Array>, exportedMimeType?: string, exportedExtension?: string}> {
    const token = await this.getValidToken(driveAccountId);

    let url = `${DRIVE_API}/files/${googleFileId}?alt=media`;
    let exportedMimeType = undefined;
    let exportedExtension = undefined;

    // Handle Google Workspace documents by exporting them
    if (mimeType && mimeType.startsWith('application/vnd.google-apps.')) {
      if (mimeType === 'application/vnd.google-apps.spreadsheet') {
        exportedMimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        exportedExtension = '.xlsx';
      } else if (mimeType === 'application/vnd.google-apps.document') {
        exportedMimeType = 'application/pdf';
        exportedExtension = '.pdf';
      } else if (mimeType === 'application/vnd.google-apps.presentation') {
        exportedMimeType = 'application/pdf';
        exportedExtension = '.pdf';
      } else {
        // Fallback for drawing, script, etc.
        exportedMimeType = 'application/pdf';
        exportedExtension = '.pdf';
      }
      url = `${DRIVE_API}/files/${googleFileId}/export?mimeType=${exportedMimeType}`;
    }

    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to download file: ${await response.text()}`);
    }

    if (!response.body) {
      throw new Error('Response body is null');
    }
    return {
      stream: response.body as ReadableStream<Uint8Array>,
      exportedMimeType,
      exportedExtension
    };
  }

  async deleteFile(driveAccountId: string, googleFileId: string): Promise<void> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/files/${googleFileId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok && response.status !== 404) {
      throw new Error(`Failed to delete file: ${await response.text()}`);
    }
  }

  async renameFile(driveAccountId: string, googleFileId: string, newName: string): Promise<void> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/files/${googleFileId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name: newName }),
    });

    if (!response.ok) {
      throw new Error(`Failed to rename file: ${await response.text()}`);
    }
  }

  // ─── Move To Another Drive Operations ───

  async shareFile(driveAccountId: string, fileId: string, emailAddress: string, role = 'writer', type = 'user'): Promise<string> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/files/${fileId}/permissions?sendNotificationEmail=false`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ role, type, emailAddress }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      try { errorData = JSON.parse(errorText); } catch {}
      throw new GoogleDriveError(response.status, `Failed to share file: ${errorText}`, errorData);
    }

    const data: { id: string } = await response.json();
    return data.id;
  }

  async revokeShare(driveAccountId: string, fileId: string, permissionId: string): Promise<void> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/files/${fileId}/permissions/${permissionId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      try { errorData = JSON.parse(errorText); } catch {}
      throw new GoogleDriveError(response.status, `Failed to revoke share: ${errorText}`, errorData);
    }
  }

  async copyFile(driveAccountId: string, fileId: string): Promise<GDriveFile> {
    const token = await this.getValidToken(driveAccountId);
    const fields = 'id,name,mimeType,size,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum';

    const response = await fetch(`${DRIVE_API}/files/${fileId}/copy?fields=${fields}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      try { errorData = JSON.parse(errorText); } catch {}
      throw new GoogleDriveError(response.status, `Failed to copy file: ${errorText}`, errorData);
    }

    return response.json();
  }

  async trashFile(driveAccountId: string, fileId: string): Promise<void> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/files/${fileId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ trashed: true }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      try { errorData = JSON.parse(errorText); } catch {}
      throw new GoogleDriveError(response.status, `Failed to trash file: ${errorText}`, errorData);
    }
  }

  async untrashFile(driveAccountId: string, fileId: string): Promise<void> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/files/${fileId}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ trashed: false }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      try { errorData = JSON.parse(errorText); } catch {}
      throw new GoogleDriveError(response.status, `Failed to untrash file: ${errorText}`, errorData);
    }
  }

  // ─── Changes API (for sync) ───

  async getStartPageToken(driveAccountId: string): Promise<string> {
    const token = await this.getValidToken(driveAccountId);

    const response = await fetch(`${DRIVE_API}/changes/startPageToken`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to get start page token: ${await response.text()}`);
    }

    const data: { startPageToken: string } = await response.json();
    return data.startPageToken;
  }

  async listChanges(
    driveAccountId: string,
    pageToken: string
  ): Promise<{
    changes: Array<{
      fileId: string;
      removed: boolean;
      file?: {
        id: string;
        name: string;
        mimeType: string;
        size?: string;
        parents?: string[];
        trashed: boolean;
        thumbnailLink?: string;
        webViewLink?: string;
        webContentLink?: string;
        createdTime: string;
        modifiedTime: string;
      };
    }>;
    nextPageToken?: string;
    newStartPageToken?: string;
  }> {
    const token = await this.getValidToken(driveAccountId);
    const fields =
      'nextPageToken,newStartPageToken,changes(fileId,removed,file(id,name,mimeType,size,parents,trashed,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum))';

    const response = await fetch(
      `${DRIVE_API}/changes?pageToken=${encodeURIComponent(pageToken)}&fields=${fields}&spaces=drive&includeRemoved=true`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    if (!response.ok) {
      throw new Error(`Failed to list changes: ${await response.text()}`);
    }

    return response.json();
  }

  async listFilesInFolder(
    driveAccountId: string,
    folderId: string
  ): Promise<
    Array<{
      id: string;
      name: string;
      mimeType: string;
      size?: string;
      thumbnailLink?: string;
      webViewLink?: string;
      webContentLink?: string;
      createdTime: string;
      modifiedTime: string;
    }>
  > {
    const token = await this.getValidToken(driveAccountId);
    const fields = 'files(id,name,mimeType,size,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum)';
    const q = encodeURIComponent(`'${folderId}' in parents and trashed = false`);

    const allFiles: Array<any> = [];
    let pageToken: string | undefined;

    do {
      const url = `${DRIVE_API}/files?q=${q}&fields=nextPageToken,${fields}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        throw new Error(`Failed to list files: ${await response.text()}`);
      }

      const data: { files: any[]; nextPageToken?: string } = await response.json();
      allFiles.push(...data.files);
      pageToken = data.nextPageToken;
    } while (pageToken);

    return allFiles;
  }

  // ─── Full Folder Contents (files + subfolders) ───

  async listFolderContents(
    driveAccountId: string,
    folderId: string
  ): Promise<{ files: GDriveFile[]; folders: GDriveFolder[] }> {
    const token = await this.getValidToken(driveAccountId);
    const fields =
      'nextPageToken,files(id,name,mimeType,size,parents,trashed,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum)';
    const q = encodeURIComponent(`'${folderId}' in parents and trashed = false`);

    const allFiles: GDriveFile[] = [];
    const allFolders: GDriveFolder[] = [];
    let pageToken: string | undefined;

    do {
      const url = `${DRIVE_API}/files?q=${q}&fields=${fields}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        throw new Error(`Failed to list folder contents: ${await response.text()}`);
      }

      const data: { files: any[]; nextPageToken?: string } = await response.json();
      
      for (const file of data.files) {
        if (file.mimeType === 'application/vnd.google-apps.shortcut') continue;
        if (file.mimeType === 'application/vnd.google-apps.folder') {
          allFolders.push(file);
        } else {
          allFiles.push(file);
        }
      }
      
      pageToken = data.nextPageToken;
    } while (pageToken);

    return { files: allFiles, folders: allFolders };
  }

  // ─── Full Drive Contents (All files + folders recursively) ───

  async listAllFilesAndFolders(
    driveAccountId: string
  ): Promise<{ files: GDriveFile[]; folders: GDriveFolder[] }> {
    const token = await this.getValidToken(driveAccountId);
    const fields =
      'nextPageToken,files(id,name,mimeType,size,parents,trashed,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum)';
    const q = encodeURIComponent(`trashed = false`);

    const allFiles: GDriveFile[] = [];
    const allFolders: GDriveFolder[] = [];
    let pageToken: string | undefined;

    do {
      const url = `${DRIVE_API}/files?q=${q}&fields=${fields}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        throw new Error(`Failed to list folder contents: ${await response.text()}`);
      }

      const data: { files: GDriveFile[]; nextPageToken?: string } = await response.json();

      for (const item of data.files) {
        if (item.mimeType === 'application/vnd.google-apps.folder') {
          allFolders.push({ id: item.id, name: item.name, parents: item.parents });
        } else if (item.mimeType !== 'application/vnd.google-apps.shortcut') {
          allFiles.push(item);
        }
      }

      pageToken = data.nextPageToken;
    } while (pageToken);

    return { files: allFiles, folders: allFolders };
  }

  async *iterateAllFilesAndFolders(
    driveAccountId: string,
    startPageToken?: string,
    parentFolderId?: string
  ): AsyncGenerator<{ files: GDriveFile[]; folders: GDriveFolder[]; nextPageToken?: string }, void, unknown> {
    const token = await this.getValidToken(driveAccountId);
    const fields =
      'nextPageToken,files(id,name,mimeType,size,parents,trashed,thumbnailLink,webViewLink,webContentLink,createdTime,modifiedTime,md5Checksum)';
    
    // If a specific parent folder is given (e.g. service account root), scope the query
    const qParts = ['trashed = false'];
    if (parentFolderId) {
      qParts.push(`'${parentFolderId}' in parents`);
    }
    const q = encodeURIComponent(qParts.join(' and '));

    let pageToken: string | undefined = startPageToken;

    // For service accounts with a specific folder, we need to recursively fetch subfolders
    const foldersToProcess: string[] = parentFolderId ? [parentFolderId] : [];
    const processedFolders = new Set<string>();

    if (parentFolderId) {
      // BFS approach: process folder by folder
      while (foldersToProcess.length > 0) {
        const currentFolder = foldersToProcess.shift()!;
        if (processedFolders.has(currentFolder)) continue;
        processedFolders.add(currentFolder);

        const folderQ = encodeURIComponent(`trashed = false and '${currentFolder}' in parents`);
        let folderPageToken: string | undefined;

        do {
          const url = `${DRIVE_API}/files?q=${folderQ}&fields=${fields}&pageSize=1000${folderPageToken ? `&pageToken=${encodeURIComponent(folderPageToken)}` : ''}`;
          const response = await fetch(url, {
            headers: { Authorization: `Bearer ${token}` },
          });

          if (!response.ok) {
            throw new Error(`Failed to list folder contents: ${await response.text()}`);
          }

          const data: { files: GDriveFile[]; nextPageToken?: string } = await response.json();

          const chunkFiles: GDriveFile[] = [];
          const chunkFolders: GDriveFolder[] = [];

          for (const item of data.files) {
            if (item.mimeType === 'application/vnd.google-apps.folder') {
              chunkFolders.push({ id: item.id, name: item.name, parents: item.parents });
              foldersToProcess.push(item.id);
            } else if (item.mimeType !== 'application/vnd.google-apps.shortcut') {
              chunkFiles.push(item);
            }
          }

          yield { files: chunkFiles, folders: chunkFolders, nextPageToken: data.nextPageToken };
          folderPageToken = data.nextPageToken;
        } while (folderPageToken);
      }
    } else {
      // Original behavior: list all files across the entire drive
      do {
        const url = `${DRIVE_API}/files?q=${q}&fields=${fields}&pageSize=1000${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`;
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!response.ok) {
          throw new Error(`Failed to list folder contents: ${await response.text()}`);
        }

        const data: { files: GDriveFile[]; nextPageToken?: string } = await response.json();

        const chunkFiles: GDriveFile[] = [];
        const chunkFolders: GDriveFolder[] = [];

        for (const item of data.files) {
          if (item.mimeType === 'application/vnd.google-apps.folder') {
            chunkFolders.push({ id: item.id, name: item.name, parents: item.parents });
          } else if (item.mimeType !== 'application/vnd.google-apps.shortcut') {
            chunkFiles.push(item);
          }
        }

        yield { files: chunkFiles, folders: chunkFolders, nextPageToken: data.nextPageToken };
        
        pageToken = data.nextPageToken;
      } while (pageToken);
    }
  }
}
