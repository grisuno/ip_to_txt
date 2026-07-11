# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis.

**Total Files Parsed:** 3 | **Total Symbols Extracted:** 32 | **Total Imports:** 19

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray: 5 5,color:#aaa;
    main_go["main.go (go)"]
    class main_go mod;
    main_go_initDB["initDB"]
    class main_go_initDB fn;
    main_go --> main_go_initDB
    main_go_getLastCheckpoint["getLastCheckpoint"]
    class main_go_getLastCheckpoint fn;
    main_go --> main_go_getLastCheckpoint
    main_go_setCheckpoint["setCheckpoint"]
    class main_go_setCheckpoint fn;
    main_go --> main_go_setCheckpoint
    main_go_wasIPProcessed["wasIPProcessed"]
    class main_go_wasIPProcessed fn;
    main_go --> main_go_wasIPProcessed
    main_go_ipToInt["ipToInt"]
    class main_go_ipToInt fn;
    main_go --> main_go_ipToInt
    ip_to_db_py["ip_to_db.py (py)"]
    class ip_to_db_py mod;
    ip_to_db_py_is_private_ip["is_private_ip"]
    class ip_to_db_py_is_private_ip fn;
    ip_to_db_py --> ip_to_db_py_is_private_ip
    ip_to_db_py_ip_to_domain["ip_to_domain"]
    class ip_to_db_py_ip_to_domain fn;
    ip_to_db_py --> ip_to_db_py_ip_to_domain
    ip_to_db_py_process_page["process_page"]
    class ip_to_db_py_process_page fn;
    ip_to_db_py --> ip_to_db_py_process_page
    ip_to_db_py_ip_to_int["ip_to_int"]
    class ip_to_db_py_ip_to_int fn;
    ip_to_db_py --> ip_to_db_py_ip_to_int
    ip_to_db_py_generate_ips["generate_ips"]
    class ip_to_db_py_generate_ips fn;
    ip_to_db_py --> ip_to_db_py_generate_ips
    app_py["app.py (py)"]
    class app_py mod;
    app_py_is_private_ip["is_private_ip"]
    class app_py_is_private_ip fn;
    app_py --> app_py_is_private_ip
    app_py_ip_to_int["ip_to_int"]
    class app_py_ip_to_int fn;
    app_py --> app_py_ip_to_int
    app_py_generate_ips["generate_ips"]
    class app_py_generate_ips fn;
    app_py --> app_py_generate_ips
    app_py_int_to_ip["int_to_ip"]
    class app_py_int_to_ip fn;
    app_py --> app_py_int_to_ip
    app_py_main["main"]
    class app_py_main fn;
    app_py --> app_py_main
    ext_concurrent_futures["concurrent.futures"]
    class ext_concurrent_futures ext;
    app_py -.->|imports| ext_concurrent_futures
    ip_to_db_py -.->|imports| ext_concurrent_futures
    ext_requests["requests"]
    class ext_requests ext;
    ip_to_db_py -.->|imports| ext_requests
    ext_bs4["bs4"]
    class ext_bs4 ext;
    ip_to_db_py -.->|imports| ext_bs4
    ext_socket["socket"]
    class ext_socket ext;
    ip_to_db_py -.->|imports| ext_socket
    ext_sqlite3["sqlite3"]
    class ext_sqlite3 ext;
    ip_to_db_py -.->|imports| ext_sqlite3
    ext_database_sql["sql"]
    class ext_database_sql ext;
    main_go -.->|imports| ext_database_sql
    ext_flag["flag"]
    class ext_flag ext;
    main_go -.->|imports| ext_flag
    ext_fmt["fmt"]
    class ext_fmt ext;
    main_go -.->|imports| ext_fmt
    ext_log["log"]
    class ext_log ext;
    main_go -.->|imports| ext_log
    ext_net["net"]
    class ext_net ext;
    main_go -.->|imports| ext_net
    ext_net_http["http"]
    class ext_net_http ext;
    main_go -.->|imports| ext_net_http
    ext_os_exec["exec"]
    class ext_os_exec ext;
    main_go -.->|imports| ext_os_exec
    ext_regexp["regexp"]
    class ext_regexp ext;
    main_go -.->|imports| ext_regexp
    ext_strings["strings"]
    class ext_strings ext;
    main_go -.->|imports| ext_strings
    ext_sync["sync"]
    class ext_sync ext;
    main_go -.->|imports| ext_sync
    ext_time["time"]
    class ext_time ext;
    main_go -.->|imports| ext_time
    ext_github_com_mattn_go_sqlite3["go-sqlite3"]
    class ext_github_com_mattn_go_sqlite3 ext;
    main_go -.->|imports| ext_github_com_mattn_go_sqlite3
    ext_golang_org_x_net_html["html"]
    class ext_golang_org_x_net_html ext;
    main_go -.->|imports| ext_golang_org_x_net_html
```

---

## Architecture Reference

### GO (1 files)

#### `main.go`
**Path:** `main.go`

**Functions:**
- `initDB` (line 35) - *initDB inicializa la base de datos*
- `getLastCheckpoint` (line 65) - *getLastCheckpoint devuelve la última IP escaneada por el algoritmo*
- `setCheckpoint` (line 75) - *setCheckpoint guarda la última IP procesada*
- `wasIPProcessed` (line 85) - *wasIPProcessed verifica si una IP ya fue procesada como PTR*
- `ipToInt` (line 92) - *ipToInt convierte IP string a uint32*
- `intToIP` (line 104) - *intToIP convierte uint32 a string IP*
- `isPrivateIP` (line 114) - *isPrivateIP verifica si una IP es privada*
- `reverseDNS` (line 123) - *reverseDNS realiza lookup inverso*
- `extractTitle` (line 132) - *extractTitle extrae el <title> de HTML*
- `fetchTitle` (line 151) - *fetchTitle intenta HTTP y luego HTTPS*
- `resolveDomainToIP` (line 178) - *resolveDomainToIP resuelve un dominio a IP pública*
- `getRootDomain` (line 195) - *getRootDomain extrae el dominio raíz (ej: google.com de mail.google.com)*
- `runCrtSh` (line 222) - *runCrtSh busca subdominios usando crt.sh*
- `contains` (line 252) - *contains verifica si un slice tiene un string*
- `union` (line 262) - *union combina dos slices sin duplicados*
- `saveToDB` (line 281) - *saveToDB guarda un registro con source*
- `processPTRIP` (line 294) - *processPTRIP procesa una IP: PTR → dominio → web → crt.sh → subdominios*
- `scanIPsWithPTR` (line 361) - *scanIPsWithPTR escanea desde la última IP guardada + 1*
- `main` (line 422)

### PY (2 files)

#### `app.py`
**Path:** `app.py`

**Functions:**
- `is_private_ip` (line 3)
- `ip_to_int` (line 16)
- `generate_ips` (line 20)
- `int_to_ip` (line 33)
- `main` (line 36)

#### `ip_to_db.py`
**Path:** `ip_to_db.py`

**Functions:**
- `is_private_ip` (line 8)
- `ip_to_domain` (line 20)
- `process_page` (line 28)
- `ip_to_int` (line 43)
- `generate_ips` (line 48)
- `int_to_ip` (line 66)
- `save_to_db` (line 70)
- `main` (line 79)
