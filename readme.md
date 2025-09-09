## ライセンス
> Copyright (C) 2025 @kiyu4776  
> This file is proprietary and confidential.  
> Unauthorized reproduction or distribution is prohibited.  

```mermaid
graph TD
    A[test/] --> B[app.js]
    A --> C[public/]
    A --> D[private/]
    A --> E[date/]
    
    C --> C1[index.html]
    C --> C2[secure.html]
    
    D --> D1[Script.html]
    
    E --> E1[date.json]
    
    %% 依存関係
    B -. 読み込み .-> E1
    C2 -. アクセス .-> D1
    C1 -. POST .-> B
