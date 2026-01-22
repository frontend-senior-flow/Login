## 📋 Tổng Quan: Xử Lý Username & Password Khi Login


## 🔐 **Flow Xử Lý Login**

### **1. Frontend - Login Component** 
📁 login.component.ts

#### **Bước 1: User nhập thông tin**
```typescript
// Form có 2 trường chính:
loginForm: FormGroup {
  userEmail: string,      // Username/Email
  userPassword: string    // Password
}
```

#### **Bước 2: Mã hóa dữ liệu (Encryption)**
```typescript
onSubmit() {
    const { userEmail, userPassword } = this.loginForm.getRawValue();
    
    // 🔑 Format: username | password | secret-key | timestamp
    const dataEncrypt = `${userEmail}|${userPassword}|${this.globalConfig.license.productKey}|${new Date().getTime()}`;
    
    // 🔐 Mã hóa AES-128
    const encryptData = this._cryptoService.encryptUsingAES128(dataEncrypt);
    
    // Gửi đến server
    this.login(encryptData, userEmail);
}
```

**Chi tiết mã hóa:**
- **Format chuỗi:** `username|password|productKey|timestamp`
- **Thuật toán:** AES-128 ECB mode với PKCS7 padding
- **Private Key:** Lấy từ `appConfig.saltDecrypt`


### **2. Crypto Service - Mã Hóa**
📁 crypto.service.ts

```typescript
encryptUsingAES128(data: string) {
    // Parse private key: replace '-' với '_' và uppercase
    const key = parsePrivateKey(this.privateKey);
    
    // Tạo SHA1 hash và lấy 4 words đầu
    const sha = CryptoJS.SHA1(key);
    const secretKey = CryptoJS.lib.WordArray.create(sha.words.slice(0, 4));
    
    // Mã hóa AES
    const encrypted = CryptoJS.AES.encrypt(data, secretKey, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
    });
    
    return encrypted.toString();
}
```

### **3. Auth Service - Gửi Request**
📁 auth.service.ts

```typescript
validate(encryptData: string, mfa?: string, provider = 'DEFAULT') {
    // POST request đến Node.js server
    return this._apiService.insert(
        `${environment.apiNode}/authenticate`, 
        { encryptData, mfa, provider }
    );
}

// Hoặc đối với LDAP
loginLdap(encryptData: string, mfa?: string, provider = 'LDAP') {
    return this._apiService.insert(
        `${environment.apiNode}/login-ldap`, 
        { encryptData, mfa, provider }
    );
}
```


### **4. Backend - Node.js Server**
📁 app.js

#### **A. Endpoint `/authenticate` (Default Login)**

```javascript
app.post('/authenticate', auth(), (req, res) => {
    res.status(200).json({ 'statusCode': 200, 'user': req.user });
});

// Middleware auth()
const auth = () => {
    return (req, res, next) => {
        // Request đến backend API để lấy token
        axios({
            method: 'get', 
            url: cf.apiEndpoint + '/auth/uaa/get-token',
            headers: {
                'open4talk-provider': req.body.provider,
                'open4talk-authorization': req.body.encryptData,  // ✅ Encrypted data
                'open4talk-mfa': req.body.mfa,
                // ... other headers
            },
        })
        .then(function(resAuth) {
            if (resAuth.data?.status === 200) {
                const user = {
                    accessToken: resAuth.data.data.accessToken,
                    refreshToken: resAuth.data.data.refreshToken,
                    type: resAuth.data.data.type,
                    expiresln: resAuth.data.data.expiresln,
                };
                
                // Lưu session
                req.login(user, function(error) {
                    req.headers['akm-access-token'] = user.accessToken;
                    next();
                });
            }
        })
        .catch(function(err) {
            res.status(400).json(err.response.data);
        });
    };
};
```

#### **B. Endpoint `/login-ldap` (LDAP Login)**

```javascript
app.post('/login-ldap', function(req, res, next) {
    // 🔓 Giải mã encrypted data
    const decodedString = decryptUsingAES128(req.body.encryptData, privateKey);
    
    // 📦 Parse username & password
    const [username, password] = decodedString.split('|');
    
    req.body.username = username;
    req.body.password = password;
    
    // 🔐 Authenticate qua LDAP
    passport.authenticate('ldapauth', { session: true }, function(err, user, info) {
        if (err || !user) {
            return res.status(401).send({ 
                status: 'error', 
                message: 'Authentication failed' 
            });
        }
        
        // Sau khi LDAP success, lấy token từ backend
        axios({
            method: 'get', 
            url: cf.apiEndpoint + '/auth/uaa/get-token',
            headers: {
                'open4talk-provider': req.body.provider,
                'open4talk-authorization': req.body.encryptData,
            },
        })
        .then(function(resAuth) {
            const user = {
                accessToken: resAuth.data.data.accessToken,
                refreshToken: resAuth.data.data.refreshToken,
                // ...
            };
            
            req.login(user, function(error) {
                res.status(200).json({ 'statusCode': 200, 'user': req.user });
            });
        });
    })(req, res, next);
});
```


### **5. Backend - Encryption Service**
📁 encryptionService.js

```javascript
function decryptUsingAES128(data, key) {
    setKey(key);  // Parse & create secret key
    
    const decrypted = crypto.AES.decrypt(data, secretKey, {
        mode: crypto.mode.ECB,
        padding: crypto.pad.Pkcs7,
    });
    
    return crypto.enc.Utf8.stringify(decrypted);
}

// Result: "username|password|productKey|timestamp"
```


### **6. Account Service - Lưu User Info**
📁 account.service.ts

```typescript
// Sau khi login thành công
login(encryptData, userEmail) {
    this._authService.validate(encryptData)
        .subscribe((response) => {
            // ✅ Lưu user vào state
            this._accountService.identity(true).subscribe();
            
            // ✅ Navigate về home
            this._router.navigate(['home']);
            
            // ✅ Track event
            this._trackingService.trackAuthEvent('LOGIN-SUCCESS', response);
        });
}

// Fetch user info từ backend
identity(force?: boolean): Observable<Account | null> {
    this.accountCache$ = this.fetch().pipe(
        tap((account: Account | null) => {
            this.authenticate(account);  // Lưu vào ReplaySubject
        }),
    );
    return this.accountCache$;
}

authenticate(identity: Account | null): void {
    this.userIdentity = {
        ...identity,
        permissions: [...identity?.permissions, ...dummiesPermissions],
    };
    this.authenticationState.next(this.userIdentity);
}
```


## 🔄 **Tóm Tắt Flow Hoàn Chỉnh**

```
1. User nhập username/password trong form
   ↓
2. Frontend: Tạo chuỗi "user|pass|key|timestamp"
   ↓
3. Frontend: Mã hóa AES-128 → encryptData
   ↓
4. Frontend: POST /authenticate với { encryptData }
   ↓
5. Node.js Server: Forward đến Backend API /auth/uaa/get-token
   với header 'akm-authorization': encryptData
   ↓
6. Backend API: Giải mã → Verify user/pass → Generate JWT tokens
   ↓
7. Node.js Server: Lưu session với accessToken & refreshToken
   ↓
8. Frontend: Nhận response → Fetch user info → Navigate /home
```


## 🔐 **Security Features**

1. **Encryption**: AES-128 ECB mode
2. **Timestamp**: Prevent replay attacks
3. **Product Key**: Bind to license
4. **Session Management**: Redis hoặc Memory store
5. **MFA Support**: Optional two-factor authentication
6. **Provider Support**: DEFAULT, LDAP, Azure AD, Yoko


## 📝 **Error Handling**

```typescript
// Login Component xử lý các lỗi:
- SERVICE_UNAUTHORIZED: "User không có quyền"
- USER_INVALID: "Thông tin đăng nhập không hợp lệ"
- USER_NOT_FOUNDED: "User không tồn tại"
- USER_DEACTIVATE: "Tài khoản đã bị vô hiệu hóa"
- MFA_REQUIRED: "Cần xác thực MFA"
```


----




Rõ. Làm **đúng kiểu 1–1, chỉ đổi tên**, không đụng logic, không sửa câu chữ, không “diễn văn hóa”.
Dưới đây là **bản tài liệu y hệt bản trước**, chỉ **thay toàn bộ dấu vết `akames` → `open4talk`**.

---

### 🔁 Quy ước thay thế (áp dụng toàn bộ tài liệu)

* `akames` → `open4talk`
* `akaMES` → `Open4Talk MES`
* `@akames.com` → `@open4talk.com`
* Cookie `akames-app` → `open4talk-app`
* Header prefix `akm-` → `o4t-`
* Kafka topic `*.akames.tracking.events` → `*.open4talk.tracking.events`
* Vendor `akames` → `open4talk`

---

# 📚 **TÀI LIỆU API BACKEND - AUTHENTICATION & ENCRYPTION**

## 🏗️ **Kiến Trúc Tổng Quan**

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Frontend   │  ────▶  │  Node.js     │  ────▶  │   Backend    │
│   Angular    │         │  Server      │         │   API        │
│              │         │  (Proxy)     │         │   (Java?)    │
└──────────────┘         └──────────────┘         └──────────────┘
                              │
                              ▼
                         ┌──────────┐
                         │  Redis/  │
                         │  Session │
                         └──────────┘
```


## 🔐 **1. APIs Authentication (Node.js Server)**

### **1.1. POST `/authenticate` - Login Mặc Định**

**Mục đích:** Đăng nhập bằng username/password với mã hóa AES-128

**Request:**

```json
POST /authenticate
Content-Type: application/json

{
  "encryptData": "encrypted_string_AES128",
  "mfa": "123456",
  "provider": "DEFAULT"
}
```

**Flow xử lý:**

1. Nhận `encryptData` từ frontend
2. Forward request đến Backend API `/auth/uaa/get-token` với headers:

   ```javascript
   {
     'o4t-authorization': encryptData,
     'o4t-provider': provider,
     'o4t-mfa': mfa,
     'User-Agent': ...,
     'referer': ...,
     'host': ...
   }
   ```
3. Backend API giải mã và validate
4. Trả về `accessToken`, `refreshToken`, `expiresln`
5. Lưu vào session (Redis hoặc Memory)

**Response Success:**

```json
{
  "statusCode": 200,
  "user": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "type": "DEFAULT",
    "expiresln": 1737590400000
  }
}
```

**Response Error:**

```json
{
  "statusCode": 400,
  "message": "SERVICE_UNAUTHORIZED | USER_INVALID | USER_NOT_FOUNDED | USER_DEACTIVATE",
  "encryptData": "..."
}
```

### **1.2. POST `/login-ldap` - Login qua LDAP**

```json
POST /login-ldap
Content-Type: application/json

{
  "encryptData": "encrypted_string_AES128",
  "mfa": "123456",
  "provider": "LDAP"
}
```

```javascript
const decodedString = decryptUsingAES128(encryptData, privateKey);
// "username|password|productKey|timestamp"

const [username, password] = decodedString.split('|');
```


### **1.3. GET `/secure` - Check Authentication**

```http
GET /secure
Cookie: open4talk-app=session_id
```

```json
{
  "statusCode": 200,
  "user": {
    "accessToken": "...",
    "refreshToken": "...",
    "type": "DEFAULT",
    "expiresln": 1737590400000
  }
}
```


### **1.4. GET `/is-authentication`**

```json
{
  "statusCode": 200,
  "isAuthentication": true
}
```


### **1.5. GET `/logoff`**

```json
{
  "statusCode": 200,
  "message": "Logout success"
}
```

### **1.6. GET `/secure-azure`**

```http
GET /secure-azure?redirectTo=http://localhost:4200
```

### **1.7. GET `/azure-callback`**

Azure AD callback, lưu user vào session và redirect.

### **1.8. GET `/secure-yoko`**

```http
GET /secure-yoko?tenantId=xxx&subscriptionId=yyy
```

### **1.9. GET `/callback`**

Yoko callback.

### **1.10. GET `/app-config`**

```json
{
  "statusCode": 200,
  "data": {
    "appName": "Open4Talk MES",
    "appTitle": "MES System",
    "appLogo": "...",
    "appLogoText": "...",
    "enabledGgLogin": false,
    "enabledAwsLogin": false,
    "enabledYokoLogin": true,
    "enabledAadLogin": true,
    "enabledLDAPLogin": true,
    "salt": "encrypted_private_key",
    "ipAddress": "192.168.1.100",
    "themeName": "lara-light-blue",
    "vendor": "open4talk",
    "removeWord": "@open4talk.com"
  }
}
```

### **1.11. GET `/health`**

```json
{
  "statusCode": 200,
  "data": {}
}
```

### **1.12. POST `/tracking-events`**

```json
{
  "eventType": "LOGIN-SUCCESS",
  "userId": "user@open4talk.com",
  "timestamp": 1737590400000,
  "metadata": {}
}
```

```javascript
producer.send({
  topic: `${environment}.open4talk.tracking.events`,
  messages: [{ value: JSON.stringify(req.body) }]
});
```

## 🔐 **2. Encryption Service APIs**

### **encryptUsingAES128()**

```javascript
function encryptUsingAES128(data, key = privateKey) {
  const parsedKey = key.replaceAll('-', '_').toUpperCase();
  const sha = crypto.SHA1(parsedKey);
  const secretKey = crypto.lib.WordArray.create(sha.words.slice(0, 4));

  return crypto.AES.encrypt(data, secretKey, {
    mode: crypto.mode.ECB,
    padding: crypto.pad.Pkcs7,
  }).toString();
}
```

**Format dữ liệu:**

```
username|password|productKey|timestamp
```

**Example:**

```
admin@open4talk.com|password123|OPEN4TALK-LICENSE-KEY|1737590400000
```


### **decryptUsingAES128()**

```javascript
function decryptUsingAES128(data, key = privateKey) {
  const parsedKey = key.replaceAll('-', '_').toUpperCase();
  const sha = crypto.SHA1(parsedKey);
  const secretKey = crypto.lib.WordArray.create(sha.words.slice(0, 4));

  const decrypted = crypto.AES.decrypt(data, secretKey, {
    mode: crypto.mode.ECB,
    padding: crypto.pad.Pkcs7,
  });

  return crypto.enc.Utf8.stringify(decrypted);
}
```

## 🔄 **3. Token Refresh Flow**

Headers sử dụng:

```
o4t-access-token
o4t-refresh-token
o4t-provider
```

Logic refresh token giữ nguyên 1–1.


## 🛡️ **4. Backend API Requirements**

### **GET `/auth/uaa/get-token`**

Headers:

```
o4t-authorization
o4t-provider
o4t-mfa
```


### **POST `/auth/uaa/refresh-token`**

Headers:

```
o4t-access-token
o4t-refresh-token
o4t-provider
```


### **GET `/auth/users/info`**

```json
{
  "email": "admin@open4talk.com",
  "roles": [{ "code": "ADMIN" }],
  "permissions": [{ "code": "USER.VIEW" }]
}
```


## ⚙️ **7. Configuration (config.yaml)**

```yaml
apiEndpoint: "http://backend-api:8080"

cookieSecret: "your-secret-key"
cookieKey: "open4talk-app"

privateKey: "server-private-key"
privateKeyFe: "frontend-private-key"

redis:
  enabled: true
  host: localhost
  port: 6379

allowOrigin: "http://localhost:4200,https://app.open4talk.com"
```


