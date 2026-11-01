/**
 * Bhadoo Drive Index — Cloudflare Worker (Wrangler / module syntax)
 *
 * All credentials and config come from environment bindings (secrets + vars).
 * Nothing sensitive is hard-coded. Set secrets with:
 *
 *   wrangler secret put GOOGLE_CLIENT_ID
 *   wrangler secret put GOOGLE_CLIENT_SECRET
 *   wrangler secret put GOOGLE_REFRESH_TOKEN
 *   wrangler secret put SERVICE_ACCOUNT_JSON   # only if USE_SERVICE_ACCOUNT=true
 */

// ─── helpers ────────────────────────────────────────────────────────────────

function buildAuthConfig(env) {
    const roots = JSON.parse(env.ROOTS || '[{"id":"root","name":"My Drive","protect_file_link":false}]');
    return {
        siteName:                   env.SITE_NAME || 'Bhadoo Drive Index',
        client_id:                  env.GOOGLE_CLIENT_ID || '',
        client_secret:              env.GOOGLE_CLIENT_SECRET || '',
        refresh_token:              env.GOOGLE_REFRESH_TOKEN || '',
        service_account:            env.USE_SERVICE_ACCOUNT === 'true',
        service_account_json:       env.SERVICE_ACCOUNT_JSON ? JSON.parse(env.SERVICE_ACCOUNT_JSON) : {},
        files_list_page_size:       parseInt(env.FILES_LIST_PAGE_SIZE || '50', 10),
        search_result_list_page_size: parseInt(env.SEARCH_RESULT_LIST_PAGE_SIZE || '50', 10),
        enable_cors_file_down:      env.ENABLE_CORS_FILE_DOWN === 'true',
        enable_password_file_verify: env.ENABLE_PASSWORD_FILE_VERIFY !== 'false',
        roots,
    };
}

function buildUiConfig(env) {
    return {
        theme:                   env.UI_THEME || 'slate',
        version:                 env.UI_VERSION || '2.0.18-beta.1',
        logo_image:              env.UI_LOGO_IMAGE !== 'false',
        logo_height:             env.UI_LOGO_HEIGHT || '',
        logo_width:              env.UI_LOGO_WIDTH || '100px',
        favicon:                 env.UI_FAVICON || '',
        logo_link_name:          env.UI_LOGO_LINK_NAME || '',
        fixed_header:            env.UI_FIXED_HEADER !== 'false',
        header_padding:          env.UI_HEADER_PADDING || '60',
        fixed_footer:            env.UI_FIXED_FOOTER === 'true',
        header_style_class:      env.UI_HEADER_STYLE_CLASS || 'navbar-dark bg-primary',
        footer_style_class:      env.UI_FOOTER_STYLE_CLASS || 'bg-primary',
        css_a_tag_color:         env.UI_CSS_A_TAG_COLOR || 'white',
        css_p_tag_color:         env.UI_CSS_P_TAG_COLOR || 'white',
        folder_text_color:       env.UI_FOLDER_TEXT_COLOR || 'white',
        loading_spinner_class:   env.UI_LOADING_SPINNER_CLASS || 'text-light',
        search_button_class:     env.UI_SEARCH_BUTTON_CLASS || 'btn-outline-success',
        path_nav_alert_class:    env.UI_PATH_NAV_ALERT_CLASS || 'alert alert-primary',
        file_view_alert_class:   env.UI_FILE_VIEW_ALERT_CLASS || 'alert alert-danger',
        file_count_alert_class:  env.UI_FILE_COUNT_ALERT_CLASS || 'alert alert-secondary',
        contact_link:            env.UI_CONTACT_LINK || '',
        copyright_year:          env.UI_COPYRIGHT_YEAR || String(new Date().getFullYear()),
        company_name:            env.UI_COMPANY_NAME || '',
        company_link:            env.UI_COMPANY_LINK || '',
        credit:                  env.UI_CREDIT !== 'false',
        display_size:            env.UI_DISPLAY_SIZE !== 'false',
        display_time:            env.UI_DISPLAY_TIME === 'true',
        display_download:        env.UI_DISPLAY_DOWNLOAD !== 'false',
        disable_player:          env.UI_DISABLE_PLAYER === 'true',
        custom_srt_lang:         env.UI_CUSTOM_SRT_LANG || '',
        disable_video_download:  env.UI_DISABLE_VIDEO_DOWNLOAD === 'true',
        second_domain_for_dl:    env.UI_SECOND_DOMAIN_FOR_DL === 'true',
        downloaddomain:          env.UI_DOWNLOAD_DOMAIN || '',
        poster:                  env.UI_POSTER || '',
        audioposter:             env.UI_AUDIO_POSTER || '',
        jsdelivr_cdn_src:        env.UI_JSDELIVR_CDN_SRC || 'https://cdn.jsdelivr.net/gh/XcodersHub/bhadoo-drive-index',
        render_head_md:          env.UI_RENDER_HEAD_MD !== 'false',
        render_readme_md:        env.UI_RENDER_README_MD !== 'false',
        display_drive_link:      env.UI_DISPLAY_DRIVE_LINK === 'true',
        plyr_io_version:         env.UI_PLYR_IO_VERSION || '3.6.4',
        plyr_io_video_resolution: env.UI_PLYR_IO_VIDEO_RES || '16:9',
        unauthorized_owner_link:  env.UI_UNAUTHORIZED_OWNER_LINK || '',
        unauthorized_owner_email: env.UI_UNAUTHORIZED_OWNER_EMAIL || '',
        arc_code:                env.UI_ARC_CODE || '',
    };
}

// ─── HTML template ───────────────────────────────────────────────────────────

function renderHtml(current_drive_order = 0, model = {}, authConfig, uiConfig) {
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0,maximum-scale=1.0, user-scalable=no"/>
  <title>${authConfig.siteName}</title>
  ${uiConfig.arc_code ? `<script async src="https://arc.io/widget.min.js#${uiConfig.arc_code}"></script>` : ''}
  <meta name="robots" content="noindex" />
  <link rel="icon" href="${uiConfig.favicon}">
  <script>
    window.drive_names = JSON.parse('${JSON.stringify(authConfig.roots.map(it => it.name))}');
    window.MODEL = JSON.parse('${JSON.stringify(model)}');
    window.current_drive_order = ${current_drive_order};
    window.UI = JSON.parse('${JSON.stringify(uiConfig)}');
  </script>
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
  <link rel="stylesheet" href="https://cdn.plyr.io/${uiConfig.plyr_io_version}/plyr.css" />
  <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.0.0/dist/${uiConfig.theme}/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
  <style>
  a { color: ${uiConfig.css_a_tag_color}; }
  p { color: ${uiConfig.css_p_tag_color}; }
  </style>
  <script src="${uiConfig.jsdelivr_cdn_src}@${uiConfig.version}/js/app.min.js"></script>
  <script src="https://cdn.jsdelivr.net/gh/XcodersHub/bhadoo-drive-index@master/js/update.min.js"></script>
  <script src="https://cdn.jsdelivr.net/gh/mozilla/pdf.js@gh-pages/build/pdf.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
</head>
<body>
</body>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.bundle.min.js" integrity="sha384-p34f1UUtsS3wqzfto5wAAmdvj+osOnFyQFpp4Ua3gs/ZVWx6oOypYoCJhGGScy+8" crossorigin="anonymous"></script>
  <script src="https://cdn.plyr.io/${uiConfig.plyr_io_version}/plyr.polyfilled.js"></script>
</html>`;
}

function renderUnauthorized(uiConfig) {
    return `<html>
<head><title>401 Unauthorized</title></head>
<body>
<center><h1>401 Unauthorized</h1></center>
<hr><center>gdi.js.org/2.0.18</center>
<hr><center>Please contact <a href="${uiConfig.unauthorized_owner_link}">Site Owner</a> at ${uiConfig.unauthorized_owner_email}</center>
</body>
</html>`;
}

function renderNotFound(uiConfig) {
    return `<html>
<head><title>404 File Not Found</title></head>
<body>
<center><h1>404 File Not Found</h1></center>
<hr><center>gdi.js.org/2.0.18</center>
<hr><center>Please contact <a href="${uiConfig.unauthorized_owner_link}">Site Owner</a> at ${uiConfig.unauthorized_owner_email}</center>
</body>
</html>`;
}

// ─── Encoding helpers (preserved from original) ───────────────────────────────

function gdiencode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p1) => String.fromCharCode('0x' + p1)));
}

function rewrite(str) {
    const sa = str.split('');
    const ra = sa.reverse();
    const ja = ra.join('');
    return 'Y29kZWlzcHJvdGVjdGVk' + ja + 'YmFzZTY0aXNleGNsdWRlZA==';
}

// ─── Search helper ───────────────────────────────────────────────────────────

const SearchFunction = {
    formatSearchKeyword(keyword) {
        if (!keyword) return '';
        return keyword
            .replace(/(!=)|['"=<>/\\:]/g, '')
            .replace(/[,，|(){}]/g, ' ')
            .trim();
    },
};

// ─── Drive constants ──────────────────────────────────────────────────────────

const DriveFixedTerms = {
    default_file_fields: 'parents,id,name,mimeType,modifiedTime,createdTime,fileExtension,size',
    gd_root_type: { user_drive: 0, share_drive: 1, sub_folder: 2 },
    folder_mime_type: 'application/vnd.google-apps.folder',
};

// ─── JWT / Service Account ────────────────────────────────────────────────────

const JSONWebToken = {
    header: { alg: 'RS256', typ: 'JWT' },

    async importKey(pemKey) {
        const pemDER = this.textUtils.base64ToArrayBuffer(
            pemKey.split('\n').map(s => s.trim()).filter(l => l.length && !l.startsWith('---')).join('')
        );
        return crypto.subtle.importKey('pkcs8', pemDER, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    },

    async createSignature(text, key) {
        return crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, this.textUtils.stringToArrayBuffer(text));
    },

    async generateGCPToken(serviceAccount) {
        const iat = Math.floor(Date.now() / 1000);
        const payload = {
            iss: serviceAccount.client_email,
            scope: 'https://www.googleapis.com/auth/drive',
            aud: 'https://oauth2.googleapis.com/token',
            exp: iat + 3600,
            iat,
        };
        const encPayload = btoa(JSON.stringify(payload));
        const encHeader = btoa(JSON.stringify(this.header));
        const key = await this.importKey(serviceAccount.private_key);
        const signed = await this.createSignature(encHeader + '.' + encPayload, key);
        return encHeader + '.' + encPayload + '.' +
            this.textUtils.arrayBufferToBase64(signed).replace(/\//g, '_').replace(/\+/g, '-');
    },

    textUtils: {
        base64ToArrayBuffer(base64) {
            const bin = atob(base64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes.buffer;
        },
        stringToArrayBuffer(str) {
            const bytes = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
            return bytes.buffer;
        },
        arrayBufferToBase64(buffer) {
            let binary = '';
            const bytes = new Uint8Array(buffer);
            for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
            return btoa(binary);
        },
    },
};

// ─── GoogleDrive class ────────────────────────────────────────────────────────

class GoogleDrive {
    constructor(authConfig, uiConfig, order) {
        this.order = order;
        this.authConfig = authConfig;
        this.uiConfig = uiConfig;
        this.root = authConfig.roots[order];
        this.root.protect_file_link = this.root.protect_file_link || false;
        this.url_path_prefix = `/${order}:`;
        this.paths = {};
        this.files = {};
        this.passwords = {};
        this.id_path_cache = {};
        this.id_path_cache[this.root.id] = '/';
        this.paths['/'] = this.root.id;
    }

    async init(gds) {
        this._gds = gds;
        await this.accessToken();
        if (this.authConfig.user_drive_real_root_id) return;
        const root_obj = await (gds[0] || this).findItemById('root');
        if (root_obj && root_obj.id) {
            this.authConfig.user_drive_real_root_id = root_obj.id;
        }
    }

    async initRootType() {
        const root_id = this.root.id;
        const types = DriveFixedTerms.gd_root_type;
        if (root_id === 'root' || root_id === this.authConfig.user_drive_real_root_id) {
            this.root_type = types.user_drive;
        } else {
            const obj = await this.getShareDriveObjById(root_id);
            this.root_type = obj ? types.share_drive : types.sub_folder;
        }
    }

    basicAuthResponse(request, uiConfig) {
        const auth = this.root.auth || '';
        const _401 = new Response(renderUnauthorized(uiConfig), {
            headers: {
                'WWW-Authenticate': `Basic realm="goindex:drive:${this.order}"`,
                'content-type': 'text/html;charset=UTF-8',
            },
            status: 401,
        });
        if (!auth) return null;
        const _auth = request.headers.get('Authorization');
        if (!_auth) return _401;
        const [received_user, received_pass] = atob(_auth.split(' ').pop()).split(':');
        if (Object.prototype.hasOwnProperty.call(auth, received_user)) {
            return auth[received_user] === received_pass ? null : _401;
        }
        return _401;
    }

    async down(id, range = '', inline = false, uiConfig) {
        const url = `https://www.googleapis.com/drive/v3/files/${id}?alt=media`;
        const requestOption = await this.requestOption();
        requestOption.headers['Range'] = range;
        let res = await fetch(url, requestOption);
        if (res.ok) {
            res = new Response(res.body, res);
            this.authConfig.enable_cors_file_down && res.headers.append('Access-Control-Allow-Origin', '*');
            inline && res.headers.set('Content-Disposition', 'inline');
            return res;
        } else if (res.status === 404) {
            return new Response(renderNotFound(uiConfig), {
                status: 404,
                headers: { 'content-type': 'text/html;charset=UTF-8' },
            });
        } else {
            const errRes = await fetch(`${uiConfig.jsdelivr_cdn_src}@master/assets/DownloadError.html`);
            return new Response(await errRes.text(), {
                headers: { 'content-type': 'text/html;charset=UTF-8' },
            });
        }
    }

    async file(path) {
        if (this.files[path] === undefined) {
            this.files[path] = await this._file(path);
        }
        return this.files[path];
    }

    async _file(path) {
        const arr = path.split('/');
        let name = arr.pop();
        name = decodeURIComponent(name).replace(/'/g, "\\'");
        const dir = arr.join('/') + '/';
        const parent = await this.findPathId(dir);
        let url = 'https://www.googleapis.com/drive/v3/files';
        const params = {
            includeItemsFromAllDrives: true,
            supportsAllDrives: true,
            q: `'${parent}' in parents and name = '${name}' and trashed = false`,
            fields: 'files(id, name, mimeType, size ,createdTime, modifiedTime, iconLink, thumbnailLink)',
        };
        url += '?' + this.enQuery(params);
        const requestOption = await this.requestOption();
        const response = await fetch(url, requestOption);
        const obj = await response.json();
        return obj.files[0];
    }

    async list(path, page_token = null, page_index = 0) {
        if (!this.path_children_cache) this.path_children_cache = {};
        if (this.path_children_cache[path]?.[page_index]?.data) {
            const child_obj = this.path_children_cache[path][page_index];
            return { nextPageToken: child_obj.nextPageToken || null, curPageIndex: page_index, data: child_obj.data };
        }
        const id = await this.findPathId(path);
        const result = await this._ls(id, page_token, page_index);
        if (result.nextPageToken && result.data.files) {
            if (!Array.isArray(this.path_children_cache[path])) this.path_children_cache[path] = [];
            this.path_children_cache[path][result.curPageIndex] = {
                nextPageToken: result.nextPageToken,
                data: result.data,
            };
        }
        return result;
    }

    async _ls(parent, page_token = null, page_index = 0) {
        if (parent === undefined) return null;
        const params = {
            includeItemsFromAllDrives: true,
            supportsAllDrives: true,
            q: `'${parent}' in parents and trashed = false AND name !='.password'`,
            orderBy: 'folder,name,modifiedTime desc',
            fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime)',
            pageSize: this.authConfig.files_list_page_size,
        };
        if (page_token) params.pageToken = page_token;
        let url = 'https://www.googleapis.com/drive/v3/files';
        url += '?' + this.enQuery(params);
        const requestOption = await this.requestOption();
        const response = await fetch(url, requestOption);
        const obj = await response.json();
        return { nextPageToken: obj.nextPageToken || null, curPageIndex: page_index, data: obj };
    }

    async password(path) {
        if (this.passwords[path] !== undefined) return this.passwords[path];
        const file = await this.file(path + '.password');
        if (!file) {
            this.passwords[path] = null;
        } else {
            const url = `https://www.googleapis.com/drive/v3/files/${file.id}?alt=media`;
            const requestOption = await this.requestOption();
            const response = await this.fetch200(url, requestOption);
            this.passwords[path] = await response.text();
        }
        return this.passwords[path];
    }

    async getShareDriveObjById(any_id) {
        if (!any_id || typeof any_id !== 'string') return null;
        const url = `https://www.googleapis.com/drive/v3/drives/${any_id}`;
        const requestOption = await this.requestOption();
        const res = await fetch(url, requestOption);
        const obj = await res.json();
        return obj?.id ? obj : null;
    }

    async search(origin_keyword, page_token = null, page_index = 0) {
        const types = DriveFixedTerms.gd_root_type;
        const is_user_drive = this.root_type === types.user_drive;
        const is_share_drive = this.root_type === types.share_drive;
        const empty_result = { nextPageToken: null, curPageIndex: page_index, data: null };
        if (!is_user_drive && !is_share_drive) return empty_result;

        const keyword = SearchFunction.formatSearchKeyword(origin_keyword);
        if (!keyword) return empty_result;

        const words = keyword.split(/\s+/);
        const name_search_str = `name contains '${words.join("' AND name contains '")}'`;
        const params = {};
        if (is_user_drive) params.corpora = 'user';
        if (is_share_drive) {
            params.corpora = 'drive';
            params.driveId = this.root.id;
            params.includeItemsFromAllDrives = true;
            params.supportsAllDrives = true;
        }
        if (page_token) params.pageToken = page_token;
        params.q = `trashed = false AND name !='.password' AND (${name_search_str})`;
        params.fields = 'nextPageToken, files(id, name, mimeType, size, modifiedTime)';
        params.pageSize = this.authConfig.search_result_list_page_size;
        params.orderBy = 'folder,name,modifiedTime desc';

        let url = 'https://www.googleapis.com/drive/v3/files';
        url += '?' + this.enQuery(params);
        const requestOption = await this.requestOption();
        const response = await fetch(url, requestOption);
        const res_obj = await response.json();
        return { nextPageToken: res_obj.nextPageToken || null, curPageIndex: page_index, data: res_obj };
    }

    async findParentFilesRecursion(child_id, contain_myself = true) {
        const gd = this;
        const target_top_id = gd.root_type === DriveFixedTerms.gd_root_type.user_drive
            ? this.authConfig.user_drive_real_root_id
            : gd.root.id;
        const parent_files = [];
        let meet_top = false;

        async function addItsFirstParent(file_obj) {
            if (!file_obj?.parents?.length) return;
            const first_p_id = file_obj.parents[0];
            if (first_p_id === target_top_id) { meet_top = true; return; }
            const p_file_obj = await gd.findItemById(first_p_id);
            if (p_file_obj?.id) {
                parent_files.push(p_file_obj);
                await addItsFirstParent(p_file_obj);
            }
        }

        const child_obj = await gd.findItemById(child_id);
        if (contain_myself) parent_files.push(child_obj);
        await addItsFirstParent(child_obj);
        return meet_top ? parent_files : null;
    }

    async findPathById(child_id) {
        if (this.id_path_cache[child_id]) return this.id_path_cache[child_id];
        const p_files = await this.findParentFilesRecursion(child_id);
        if (!p_files?.length) return '';

        const cache = p_files.map((value, idx) => {
            const is_folder = idx === 0 ? value.mimeType === DriveFixedTerms.folder_mime_type : true;
            let path = '/' + p_files.slice(idx).map(it => it.name).reverse().join('/');
            if (is_folder) path += '/';
            return { id: value.id, path };
        });

        cache.forEach(obj => {
            this.id_path_cache[obj.id] = obj.path;
            this.paths[obj.path] = obj.id;
        });
        return cache[0].path;
    }

    async findItemById(id) {
        const is_user_drive = this.root_type === DriveFixedTerms.gd_root_type.user_drive;
        const url = `https://www.googleapis.com/drive/v3/files/${id}?fields=${DriveFixedTerms.default_file_fields}${is_user_drive ? '' : '&supportsAllDrives=true'}`;
        const requestOption = await this.requestOption();
        const res = await fetch(url, requestOption);
        return res.json();
    }

    async findPathId(path) {
        let c_path = '/';
        let c_id = this.paths[c_path];
        const arr = path.replace(/^\/|\/$/g, '').split('/').filter(Boolean);
        for (const name of arr) {
            c_path += name + '/';
            if (this.paths[c_path] === undefined) {
                this.paths[c_path] = await this._findDirId(c_id, name);
            }
            c_id = this.paths[c_path];
            if (!c_id) break;
        }
        return this.paths[path];
    }

    async _findDirId(parent, name) {
        name = decodeURIComponent(name).replace(/'/g, "\\'");
        if (!parent) return null;
        const params = {
            includeItemsFromAllDrives: true,
            supportsAllDrives: true,
            q: `'${parent}' in parents and mimeType = 'application/vnd.google-apps.folder' and name = '${name}' and trashed = false`,
            fields: 'nextPageToken, files(id, name, mimeType)',
        };
        let url = 'https://www.googleapis.com/drive/v3/files';
        url += '?' + this.enQuery(params);
        const requestOption = await this.requestOption();
        const response = await fetch(url, requestOption);
        const obj = await response.json();
        return obj.files[0]?.id ?? null;
    }

    async accessToken() {
        if (!this.authConfig.expires || this.authConfig.expires < Date.now()) {
            const obj = await this.fetchAccessToken();
            if (obj.access_token) {
                this.authConfig.accessToken = obj.access_token;
                this.authConfig.expires = Date.now() + 3500 * 1000;
            }
        }
        return this.authConfig.accessToken;
    }

    async fetchAccessToken() {
        const url = 'https://www.googleapis.com/oauth2/v4/token';
        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        let post_data;
        if (this.authConfig.service_account && this.authConfig.service_account_json) {
            const jwttoken = await JSONWebToken.generateGCPToken(this.authConfig.service_account_json);
            post_data = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwttoken };
        } else {
            post_data = {
                client_id: this.authConfig.client_id,
                client_secret: this.authConfig.client_secret,
                refresh_token: this.authConfig.refresh_token,
                grant_type: 'refresh_token',
            };
        }
        const response = await fetch(url, { method: 'POST', headers, body: this.enQuery(post_data) });
        return response.json();
    }

    async fetch200(url, requestOption) {
        let response;
        for (let i = 0; i < 3; i++) {
            response = await fetch(url, requestOption);
            if (response.status !== 403) break;
            await new Promise(r => setTimeout(r, 800 * (i + 1)));
        }
        return response;
    }

    async requestOption(headers = {}, method = 'GET') {
        const accessToken = await this.accessToken();
        headers['authorization'] = 'Bearer ' + accessToken;
        return { method, headers };
    }

    enQuery(data) {
        return Object.entries(data).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    }
}

// ─── Request handlers ─────────────────────────────────────────────────────────

async function apiRequest(request, gd, authConfig, uiConfig) {
    const url = new URL(request.url);
    let path = url.pathname.replace(gd.url_path_prefix, '') || '/';
    const option = { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } };

    if (path.endsWith('/')) {
        const form = await request.formData();
        const deferred_list_result = gd.list(path, form.get('page_token'), Number(form.get('page_index')));

        if (authConfig.enable_password_file_verify) {
            const password = await gd.password(path);
            if (password && password.replace('\n', '') !== form.get('password')) {
                return new Response('Y29kZWlzcHJvdGVjdGVk=0Xfi4icvJnclBCZy92dzNXYwJCI6ISZnF2czVWbiwSMwQDI6ISZk92YisHI6IicvJnclJyeYmFzZTY0aXNleGNsdWRlZA==', option);
            }
        }

        const list_result = await deferred_list_result;
        return new Response(rewrite(gdiencode(JSON.stringify(list_result))), option);
    } else {
        const file = await gd.file(path);
        return new Response(rewrite(gdiencode(JSON.stringify(file))), option);
    }
}

async function handleSearch(request, gd) {
    const option = { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } };
    const form = await request.formData();
    const search_result = await gd.search(form.get('q') || '', form.get('page_token'), Number(form.get('page_index')));
    return new Response(rewrite(gdiencode(JSON.stringify(search_result))), option);
}

async function handleId2Path(request, gd) {
    const option = { status: 200, headers: { 'Access-Control-Allow-Origin': '*' } };
    const form = await request.formData();
    const path = await gd.findPathById(form.get('id'));
    return new Response(path || '', option);
}

// ─── Main fetch handler (module export) ───────────────────────────────────────

export default {
    async fetch(request, env) {
        const authConfig = buildAuthConfig(env);
        const uiConfig = buildUiConfig(env);

        // Initialise drive instances per-request (Workers are stateless per isolate lifetime,
        // but we rebuild the minimal state needed each cold start).
        const gds = [];
        for (let i = 0; i < authConfig.roots.length; i++) {
            const gd = new GoogleDrive(authConfig, uiConfig, i);
            await gd.init(gds);
            gds.push(gd);
        }
        await Promise.all(gds.map(gd => gd.initRootType()));

        const url = new URL(request.url);
        const path = url.pathname;

        function redirectToIndex() {
            return new Response('', { status: 301, headers: { Location: `${url.origin}/0:/` } });
        }

        if (path === '/') return redirectToIndex();

        if (path.toLowerCase() === '/arc-sw.js') {
            return fetch('https://arc.io/arc-sw.js');
        }

        if (path.toLowerCase() === '/admin') {
            return Response.redirect('https://bit.ly/3sAxYwr', 301);
        }

        // Command routes: /<driveNum>:<command>/...
        const command_reg = /^\/(?<num>\d+):(?<command>[a-zA-Z0-9]+)(\/.*)?$/;
        const cmdMatch = command_reg.exec(path);
        if (cmdMatch) {
            const order = Number(cmdMatch.groups.num);
            if (order < 0 || order >= gds.length) return redirectToIndex();
            const gd = gds[order];
            const authFail = gd.basicAuthResponse(request, uiConfig);
            if (authFail) return authFail;

            const command = cmdMatch.groups.command;
            if (command === 'search') {
                if (request.method === 'POST') return handleSearch(request, gd);
                const q = (url.searchParams.get('q') || '').replace(/'/g, '').replace(/"/g, '');
                return new Response(renderHtml(gd.order, { q, is_search_page: true, root_type: gd.root_type }, authConfig, uiConfig), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' },
                });
            }
            if (command === 'id2path' && request.method === 'POST') {
                return handleId2Path(request, gd);
            }
        }

        // Common file/folder routes: /<driveNum>:/path/...
        const common_reg = /^\/\d+:\/.*$/;
        if (!path.match(common_reg)) return redirectToIndex();

        let gd;
        try {
            const order = Number(path.split('/')[1].slice(0, -1));
            if (order < 0 || order >= gds.length) return redirectToIndex();
            gd = gds[order];
        } catch {
            return redirectToIndex();
        }

        const basic_auth_res = gd.basicAuthResponse(request, uiConfig);
        const localPath = path.replace(gd.url_path_prefix, '') || '/';

        if (request.method === 'POST') {
            return basic_auth_res || apiRequest(request, gd, authConfig, uiConfig);
        }

        const action = url.searchParams.get('a');
        if (localPath.endsWith('/') || action !== null) {
            return basic_auth_res || new Response(renderHtml(gd.order, { root_type: gd.root_type }, authConfig, uiConfig), {
                status: 200,
                headers: { 'Content-Type': 'text/html; charset=utf-8' },
            });
        }

        // File download
        if (localPath.split('/').pop().toLowerCase() === '.password') {
            return basic_auth_res || new Response('', { status: 404 });
        }
        const file = await gd.file(localPath);
        const range = request.headers.get('Range');
        const inline = url.searchParams.get('inline') === 'true';
        if (gd.root.protect_file_link && basic_auth_res) return basic_auth_res;
        return gd.down(file?.id, range, inline, uiConfig);
    },
};
