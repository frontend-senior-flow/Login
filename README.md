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

