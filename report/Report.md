<!-- markdownlint-disable MD013 MD033 -->
<div align="center">
<h1><a id="intro">Лабораторная работа №9</a><br></h1>
<a href="https://docs.github.com/en"><img src="https://img.shields.io/static/v1?logo=github&logoColor=fff&label=&message=Docs&color=36393f&style=flat" alt="GitHub Docs"></a>
<a href="https://daringfireball.net/projects/markdown"><img src="https://img.shields.io/static/v1?logo=markdown&logoColor=fff&label=&message=Markdown&color=36393f&style=flat" alt="Markdown"></a>
<a href="https://shields.io"><img src="https://img.shields.io/static/v1?logo=shieldsdotio&logoColor=fff&label=&message=Shields&color=36393f&style=flat" alt="Shields"></a>
<img src="https://img.shields.io/badge/Course-AppSec-D51A1A?style=flat" alt="Course: AppSec">
<img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat&logo=githubactions&logoColor=white" alt="GitHub Actions">
<img src="https://img.shields.io/badge/Semgrep-1B2333?style=flat" alt="Semgrep">
<img src="https://img.shields.io/badge/Trivy-1904DA?style=flat&logo=aquasecurity&logoColor=white" alt="Trivy">
<img src="https://img.shields.io/badge/OWASP_ZAP-333333?style=flat" alt="OWASP ZAP">
<img src="https://img.shields.io/badge/Contributor-Поддоскина_С._К.-8b9aff?style=flat" alt="Contributor"></div>

***
## Задание

- [x] 1. Создайте структуру репозитория лабораторной работы и скопируйте уязвимое приложение из `lab07` или `lab08`

```bash
$ mkdir -p lab09/{app,pipeline/{sast,sca,dast},.github/workflows}
$ cp -r ../lab08/vulnerable-app/* lab09/app/
```

Было принято решение взять уязвимое приложение из `lab07`. Получилась следующая структура:

```shell
svepodd@DESKTOP-PPV5M0R:~/Lab09$ tree -a
.
├── .github
│   └── workflows
├── README.md
├── app
│   ├── Dockerfile
│   ├── app.py
│   ├── config.yaml
│   └── requirements.txt
├── docker-compose.yml
└── pipeline
    ├── dast
    ├── sast
    └── sca

8 directories, 13 files
```

- [x] 2. Разверните и убедитесь в работоспособности приложения локально перед настройкой пайплайна

```bash
$ docker-compose up -d --build
$ curl -i http://localhost:8080
```

```shell
svepodd@DESKTOP-PPV5M0R:~/Lab09$ curl -i http://localhost:8080
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 25
Server: Werkzeug/2.0.3 Python/3.11.15
Date: Sun, 24 May 2026 10:51:37 GMT

Vulnerable lab07 app v1.0
```

- [x] 3. Напишите файл `.github/workflows/devsecops.yml`. Пайплайн должен содержать пять jobs: `sast`, `sca`, `build-and-scan`, `dast`, `report`

Пять jobs, связанных через `needs:`:

```
        ┌──────────┐   ┌──────────┐
        │   sast   │   │   sca    │
        │ semgrep  │   │  dep-ch  │
        │ checkov  │   │          │
        └────┬─────┘   └────┬─────┘
             └───────┬──────┘
                     ▼
            ┌────────────────┐
            │ build-and-scan │   (trivy)
            └───────┬────────┘
                    ▼
            ┌────────────────┐
            │      dast      │   (zap)
            └───────┬────────┘
                    ▼
            ┌────────────────┐
            │     report     │   (merge_reports.py → HTML)
            └────────────────┘
```

`report` имеет `if: always()` - собирается даже если предыдущий этап упал, чтобы единый отчёт был всегда.

- [x] 4. Напишите файл `pipeline/sast/semgrep-rules.yml` — правила для обнаружения уязвимостей в Python. Минимум три правила: SQL-инъекция, жёстко заданный секрет, небезопасный `eval`

Файл `pipeline/sast/semgrep-rules.yml` содержит 8 правил:

| Описание                                              | ID                            | Что ищет                            | Severity | CWE     |
| ----------------------------------------------------- | ----------------------------- | ----------------------------------- | -------- | ------- |
| 1. SQL-инъекция                                       | `py-sql-injection`            | f-строка/конкатенация в `execute()` | ERROR    | CWE-89  |
| 2. Жёстко заданный секрет                             | `py-hardcoded-credentials`    | `DB_PASSWORD="..."` и т.п.          | ERROR    | CWE-798 |
| 3. Небезопасный eval / exec на пользовательском вводе | `py-unsafe-eval`              | `eval()`, `exec()`                  | ERROR    | CWE-95  |
| 4. Command injection через os.system / subprocess     | `py-command-injection`        | `os.system`, `subprocess sh -c`     | ERROR    | CWE-78  |
| 5. Небезопасная десериализация pickle                 | `py-insecure-deserialization` | `pickle.loads()`                    | ERROR    | CWE-502 |
| 6. Path Traversal                                     | `py-path-traversal`           | `open()` на user-пути               | WARNING  | CWE-22  |
| 7. Reflected XSS                                      | `py-reflected-xss`            | вывод user-input в HTML             | WARNING  | CWE-79  |
| 8. Flask debug=True                                   | `py-flask-debug-enabled`      | `debug=True`                        | WARNING  | CWE-489 |

- [x] 5. Напишите файл `pipeline/sast/checkov-config.yaml` — конфигурация Checkov для проверки Dockerfile и docker-compose

`pipeline/sast/checkov-config.yaml` проверяет `Dockerfile` и `docker-compose.yml` (frameworks `dockerfile`, `docker_compose`).

```yaml
framework:
  - dockerfile
  - docker_compose

soft-fail: true
quiet: false
compact: true
download_external_modules: false

file:
  - app/Dockerfile
  - docker-compose.yml

output: cli
```

Было принято решение убрать блок check по сравнению с lab07. Без него Checkov по умолчанию гоняет все docker-проверки, а не часть из них.

- [x] 6. Напишите скрипт `pipeline/sca/dependency-check.sh` для локального запуска OWASP Dependency-Check CLI

`pipeline/sca/dependency-check.sh`: локальный запуск с кэшем NVD в `~/.dependency-check-data`, режимом `--update`, `NVD_API_KEY` из env, порогом `--failOnCVSS 9`. В CI - action `dependency-check/Dependency-Check_Action@main`.

```bash
#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/pipeline/sca/reports"
PROJECT_NAME="lab09-vulnerable-app"
DATA_DIR="${HOME}/.dependency-check-data"

mkdir -p "${OUT_DIR}" "${DATA_DIR}"

echo "============================================================"
echo " OWASP Dependency-Check SCA — lab09"
echo "============================================================"

if command -v dependency-check >/dev/null 2>&1; then
  DC_CMD="dependency-check"
elif [ -x "${ROOT_DIR}/pipeline/sca/dependency-check/bin/dependency-check.sh" ]; then
  DC_CMD="${ROOT_DIR}/pipeline/sca/dependency-check/bin/dependency-check.sh"
else
  echo "[!] ERROR: 'dependency-check' CLI не найден."
  echo "    Установите: https://owasp.org/www-project-dependency-check/"
  exit 1
fi

if [ "${1:-}" = "--update" ]; then
  echo "[*] Обновление базы NVD в ${DATA_DIR}..."
  "${DC_CMD}" --updateonly --data "${DATA_DIR}" \
    ${NVD_API_KEY:+--nvdApiKey "$NVD_API_KEY"}
  echo "[+] NVD-данные обновлены."
  exit 0
fi

echo "[*] Скан requirements.txt с кэшем NVD (${DATA_DIR})"

"${DC_CMD}" \
  --scan "${ROOT_DIR}/app/requirements.txt" \
  --format HTML --format JSON \
  --project "${PROJECT_NAME}" \
  --out "${OUT_DIR}" \
  --data "${DATA_DIR}" \
  --noupdate \
  --enableExperimental \
  --failOnCVSS 9 \
  --log "${OUT_DIR}/dependency-check.log" || EXIT_CODE=$?

EXIT_CODE=${EXIT_CODE:-0}
echo ""
echo "[+] Отчёты в: ${OUT_DIR}"
exit "${EXIT_CODE}"
```

- [x] 7. Напишите скрипт `pipeline/dast/zap_scan.sh` для локального запуска OWASP ZAP

```bash
#!/usr/bin/env bash

set -euo pipefail

ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
TARGET_URL="${TARGET_URL:-http://host.docker.internal:8080}"
OUT_DIR="pipeline/dast/reports"

mkdir -p "$OUT_DIR"
cp pipeline/dast/zap-baseline.conf "$OUT_DIR/zap-baseline.conf"

echo "============================================================"
echo " OWASP ZAP baseline scan — lab09"
echo "============================================================"
echo "[i] Target: ${TARGET_URL}"

docker run --rm \
  -v "$(pwd)/$OUT_DIR":/zap/wrk \
  "$ZAP_IMAGE" \
  zap-baseline.py \
  -t "$TARGET_URL" \
  -c /zap/wrk/zap-baseline.conf \
  -J /zap/wrk/zap-report.json \
  -r /zap/wrk/zap-report.html \
  -I

echo ""
echo "[+] DAST reports saved to $OUT_DIR"
ls -lh "$OUT_DIR"/zap-report.* 2>/dev/null || echo "[!] Отчёты не найдены"
```

- [x] 8. Напишите файл `pipeline/dast/zap-baseline.conf` — конфигурация порогов ZAP. Укажите правила, которые должны вызывать FAIL (высокий риск), WARN (средний) и IGNORE (информационный)

```bash
# --- Информационные / низкоприоритетные ---
10016   WARN  (Web Browser XSS Protection Not Enabled)
10017   WARN  (Cross-Domain JavaScript Source File Inclusion)
10019   WARN  (Content-Type Header Missing)
10021   WARN  (X-Content-Type-Options Header Missing)
10023   WARN  (Information Disclosure - Debug Error Messages)
10027   WARN  (Information Disclosure - Suspicious Comments)
10049   IGNORE (Storable and Cacheable Content)
10054   WARN  (Cookie Without SameSite Attribute)
10063   WARN  (Permissions Policy Header Not Set)
10098   WARN  (Cross-Domain Misconfiguration)
90004   WARN  (Insufficient Site Isolation Against Spectre)

# --- Заголовки безопасности — критичны ---
10020   FAIL  (Missing Anti-clickjacking Header / X-Frame-Options)
10036   FAIL  (Server Leaks Version Information via Server header)
10038   FAIL  (Content Security Policy Header Not Set)
10040   FAIL  (Secure Pages Include Mixed Content)

# --- Уязвимости приложения — FAIL ---
10099   FAIL  (Source Code Disclosure)
40012   FAIL  (Cross Site Scripting - Reflected)
40014   FAIL  (Cross Site Scripting - Persistent)
40018   FAIL  (SQL Injection)
40019   FAIL  (SQL Injection - MySQL)
40022   FAIL  (SQL Injection - PostgreSQL)
90019   FAIL  (Server Side Code Injection)
90020   FAIL  (Remote OS Command Injection)
```

- [x] 9. Напишите скрипт `pipeline/merge_reports.py` для агрегации всех JSON-отчётов в единый HTML

`pipeline/merge_reports.py` читает скачанные артефакты из `pipeline/artifacts/`, нормализует находки всех инструментов в единый формат и рендерит `unified-report.html`.

- [x] 10. Сделайте первый коммит с базовой структурой и убедитесь, что пайплайн запускается в GitHub Actions

```bash
$ git add .github/ app/ pipeline/ docker-compose.yml
$ git commit -S -m "feat(lab09): add DevSecOps pipeline skeleton"
$ git push origin develop
```

```shell
svepodd@DESKTOP-PPV5M0R:~/Lab09$ git commit -S -m "ci(lab09): collect ZAP reports manually, bypass broken uploader"
[main 883948b] ci(lab09): collect ZAP reports manually, bypass broken uploader
 1 file changed, 22 insertions(+), 9 deletions(-)
svepodd@DESKTOP-PPV5M0R:~/Lab09$ git push origin main
Enumerating objects: 9, done.
Counting objects: 100% (9/9), done.
Delta compression using up to 22 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (5/5), 1.65 KiB | 1.65 MiB/s, done.
Total 5 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
To github.com:svepodd/Lab09.git
   9818a05..883948b  main -> main
```

Откройте вкладку **Actions** в репозитории GitHub и убедитесь, что workflow `DevSecOps Pipeline` запустился. Изучите логи каждого job.

- [x] 11. Проанализируйте результаты SAST: откройте артефакт `sast-reports` и изучите `semgrep-report.json` и `checkov-report.json`. Опишите каждую срабатывание — почему правило сработало и что именно уязвимо в коде

### Semgrep - 8 срабатываний

Все находки относятся к файлу `app/app.py`.

| #   | Severity | Правило                       | Строка | Уязвимый код                                                             | Почему сработало правило                                                                                                                                                                                                                        |
| --- | -------- | ----------------------------- | ------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | ERROR    | `py-sql-injection`            | 34     | `query = f"SELECT id, name, email FROM users WHERE name = '{username}'"` | SQL-запрос строится f-строкой с прямой подстановкой `username` из `request.args`. Запрос затем уходит в `cur.execute(query)`. Атакующий через `?name=' OR '1'='1` читает всю таблицу users, через `'; DROP TABLE` - уничтожает данные (CWE-89). |
| 2   | ERROR    | `py-command-injection`        | 52     | `os.system(cmd)`, где `cmd = f"ping -c 1 {host}"`                        | Команда ОС собирается из пользовательского `host` и выполняется в shell через `os.system`. Запрос `?host=8.8.8.8; rm -rf /` приводит к выполнению произвольных команд (CWE-78).                                                                 |
| 3   | ERROR    | `py-command-injection`        | 59     | `cmd = ["sh","-c", f"pg_dump mydb > {target}"]; subprocess.call(cmd)`    | Пользовательский `target` подставляется в строку, передаваемую `sh -c`. Инъекция в `target` (`; cat /etc/passwd`) даёт RCE (CWE-78).                                                                                                            |
| 4   | ERROR    | `py-insecure-deserialization` | 79     | `obj = pickle.loads(bytes.fromhex(data))`                                | `pickle.loads` десериализует данные из запроса. pickle при десериализации может выполнять произвольный код - специально сформированный payload приводит к RCE (CWE-502).                                                                        |
| 5   | ERROR    | `py-unsafe-eval`              | 88     | `result = eval(expr)`                                                    | `eval` вычисляет выражение из параметра `expr` без ограничений. `?expr=__import__('os').system('id')` исполняет любой код (CWE-95).                                                                                                             |
| 6   | ERROR    | `py-hardcoded-credentials`    | 12     | `DB_USER = "admin"`                                                      | Учётные данные зашиты в исходный код. Любой с доступом к репозиторию (и git-истории) видит их (CWE-798).                                                                                                                                        |
| 7   | ERROR    | `py-hardcoded-credentials`    | 13     | `DB_PASSWORD = "SuperSecret123"`                                         | Пароль БД в открытом виде в коде. Должен храниться в переменных окружения / секрет-менеджере (CWE-798).                                                                                                                                         |
| 8   | WARNING  | `py-flask-debug-enabled`      | 10     | `app.config["DEBUG"] = True`                                             | Включён debug-режим Flask. Интерактивный отладчик Werkzeug позволяет выполнять код через консоль (защищён только PIN), а трейсбеки раскрывают внутреннюю информацию (CWE-489).                                                                  |

**Вывод по Semgrep:** обнаружено 6 различных классов уязвимостей, четыре из которых (`SQLi`, два `command injection`, `pickle`, `eval`) ведут к удалённому выполнению кода. Это демонстрирует ценность shift-left: критические уязвимости видны на этапе анализа исходников, ещё до сборки образа.

**Сходство c lab07:** оба раза сканировался по сути один и тот же `app.py`, и ядро находок совпадает - `os.system` RCE, path traversal через `open()`, `pickle.loads`, `eval`. Это закономерно: код приложения общий.

**Различие в числах:** lab07 дал **5** находок, lab09 - **8**. Причём набор не идентичный: различие в находках Semgrep объясняется не «уязвимостью кода», а разным набором правил в `semgrep-rules.yml`. В lab07 правила `py-sql-injection-critical` и `py-hardcoded-db-credentials` были написаны под другие паттерны (конкатенация строк, а не f-строки) и не поймали f-строковый SQL-запрос. В lab09 правила переписаны точнее - поэтому они дополнительно зацепили SQLi, секреты и debug. Это хорошая иллюстрация того, что результат SAST зависит от качества правил, а не только от кода.

### Checkov - 2 FAILED (из 52 проверок, 50 passed)

Сканировался `app/Dockerfile`.

| Check          | Что нарушено                                                                                                                    | Чем опасно                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `CKV_DOCKER_3` | *Ensure that a user for the container has been created* - в Dockerfile нет инструкции `USER`, контейнер запускается под `root`. | При компрометации приложения или escape из контейнера атакующий получает root-привилегии. Нарушение принципа наименьших привилегий. |
| `CKV_DOCKER_2` | *Ensure that HEALTHCHECK instructions have been added* - отсутствует `HEALTHCHECK`.                                             | Оркестратор (Docker/K8s) не может определить, действительно ли приложение работоспособно, и не перезапустит «зависший» контейнер.   |

**Сходство c lab07:** идентичный результат. 50 passed, 2 failed - `CKV_DOCKER_2` (нет HEALTHCHECK) и `CKV_DOCKER_3` (контейнер под root). Совпадение подтверждает воспроизводимость инструмента.

- [x] 12. Проанализируйте результаты SCA: откройте артефакт `sca-reports`. Для каждой найденной CVE опишите: пакет, версия, CVSS-оценка, описание уязвимости, рекомендуемое обновление

Сканировался `app/requirements.txt`. Обнаружено **8 уязвимостей в 4 пакетах**. Job завершился с ошибкой (gate `--failOnCVSS 9`), так как присутствуют две CVE с CVSS 9.8.

| CVE              | Пакет    | Версия    | CVSS    | Severity | Описание уязвимости                                                                                                 | Рекомендуемое обновление    |
| ---------------- | -------- | --------- | ------- | -------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| CVE-2020-14343   | PyYAML   | 5.3.1     | **9.8** | Critical | Произвольное выполнение кода при обработке недоверенного YAML через `full_load` / `FullLoader`.                     | ≥ **5.4**                   |
| CVE-2023-37920   | certifi  | 2018.4.16 | **9.8** | Critical | В наборе корневых сертификатов присутствует скомпрометированный УЦ «e-Tugra», что подрывает доверие к TLS-проверке. | ≥ **2023.7.22**             |
| CVE-2018-1000805 | paramiko | 2.4.1     | 8.8     | High     | Некорректный контроль доступа в SSH-сервере paramiko, ведущий к RCE по сети.                                        | ≥ 2.4.2                     |
| CVE-2022-23491   | certifi  | 2018.4.16 | 7.5     | High     | В корневом хранилище остаются сертификаты «TrustCor», доверие к которым отозвано.                                   | ≥ **2022.12.7**             |
| CVE-2022-29217   | pyjwt    | 1.7.1     | 7.5     | High     | Algorithm confusion: атакующий выбирает алгоритм подписи JWT, что при неверной настройке позволяет подделать токен. | ≥ **2.4.0**                 |
| CVE-2026-32597   | pyjwt    | 1.7.1     | 7.5     | High     | PyJWT не валидирует заголовок `crit` (RFC 7515 §4.1.11) и принимает токены с неизвестными расширениями.             | ≥ **2.12.0**                |
| CVE-2022-24302   | paramiko | 2.4.1     | 5.9     | Medium   | Race condition между созданием и `chmod` приватного ключа в `write_private_key_file` → утечка ключа.                | ≥ **2.10.1**                |
| CVE-2023-48795   | paramiko | 2.4.1     | 5.9     | Medium   | Terrapin attack: обход проверки целостности SSH (OpenSSH < 9.6) за счёт усечения сообщения согласования расширений. | ≥ 2.5.0 / обновить SSH-стек |

**Вывод по SCA:** наибольший риск дают `PyYAML 5.3.1` и `certifi 2018.4.16` (обе - Critical, 9.8). Самый «проблемный» пакет - `paramiko 2.4.1` (3 CVE). Обновление перечисленных зависимостей до рекомендованных версий закрывает все 8 находок.

**lab07** сканировал в основном Java-зависимости из `pom.xml` (через Maven-плагин). **lab09** сканировал только Python-зависимости из `requirements.txt` и дал 8 CVE в 4 пакетах.

- [x] 13. Проанализируйте результаты Trivy: откройте `trivy-report.json`. Определите, из каких слоёв образа приходит большинство уязвимостей — из базового образа или из установленных зависимостей

Образ `lab09-app` собран на базе `python:3.11-slim` (фактически Debian 13.5). Trivy нашёл 77 уязвимостей высокого и критического уровня (7 Critical + 70 High) и чётко разделил их по двум источникам:

| Слой (Class) | Источник                                | Уязвимостей | Severity             |
| ------------ | --------------------------------------- | ----------- | -------------------- |
| `os-pkgs`    | Базовый образ Debian (системные пакеты) | 33          | 33 High              |
| `lang-pkgs`  | Python-зависимости (`pip install`)      | 44          | 7 Critical + 37 High |

Большинство (44 из 77, и все 7 Critical) приходит из установленных Python-зависимостей, а не из базового образа. Разбивка по пакетам:

Python-слой (lang-pkgs):
- **Django 2.2 - 21 уязвимость (6 Critical + 15 High)** - главный источник. Примеры Critical: CVE-2019-14234 (SQLi в JSONField), CVE-2020-7471 (SQLi в `StringAgg`), CVE-2022-28346/28347 (SQLi), CVE-2025-64459. Пакет давно устарел.
- urllib3 - 5, cryptography - 4, PyJWT - 2, Werkzeug - 2, gunicorn - 2, плюс Flask, PyYAML (Critical, CVE-2020-14343), certifi, requests, paramiko по 1–2.

OS-слой (os-pkgs Debian):
- **linux-libc-dev - 27 из 33** (заголовки ядра; большинство без доступного фикса - `fix нет`);
- по одной в libncursesw6, libtinfo6, libxml2, libxml2-dev, ncurses-base, ncurses-bin.

**Вывод по Trivy:** критический риск сосредоточен в **прикладных зависимостях** (особенно Django 2.2 с 6 critical SQLi). OS-слой даёт ровно треть находок, и они в основном из `linux-libc-dev` без доступного исправления (типичный «шум» базового образа). Практический вывод: первоочередное действие - обновить/убрать устаревшие Python-пакеты (Django вообще не используется приложением и должен быть удалён из `requirements.txt`); базовый `python:3.11-slim` уже достаточно минимален, и переход на него вместо `python:latest` оправдан.

- [x] 14. Проанализируйте результаты DAST: откройте `dast-reports/zap-report.html`. Сопоставьте находки ZAP с уязвимостями, которые вы исправляли в лабораторной работе №8. Объясните, почему автоматический сканер нашёл или не нашёл конкретную уязвимость

Baseline-скан выполнен по `http://localhost:8080`. Заголовок `Server: Werkzeug/2.0.3 Python/3.11.15` в отчёте подтверждает, что сканировалось именно наше Flask-приложение. ZAP сгенерировал 9 уникальных типов алертов (18 инстансов с учётом повторов по разным URL):

| Severity | Алерт (plugin id)                                            | Найдено               |
| -------- | ------------------------------------------------------------ | --------------------- |
| Medium   | Content Security Policy (CSP) Header Not Set (10038)         | да                    |
| Medium   | Missing Anti-clickjacking Header / X-Frame-Options (10020)   | да                    |
| Low      | Cross-Origin-Embedder/Opener/Resource-Policy Missing (90004) | да                    |
| Low      | Permissions Policy Header Not Set (10063)                    | да                    |
| Low      | Server Leaks Version Information via Server header (10036)   | да (`Werkzeug/2.0.3`) |
| Low      | X-Content-Type-Options Header Missing (10021)                | да                    |
| Info     | Storable and Cacheable Content (10049)                       | да                    |

- [x] 15. Внесите исправления в `app/app.py`, `app/Dockerfile` и `docker-compose.yml` для устранения критических находок. Запушьте изменения — пайплайн должен запуститься повторно и показать меньше срабатываний

```bash
$ git add app/
$ git commit -S -m "fix(lab09): remediate SAST and DAST findings"
$ git push origin develop
```

```shell
svepodd@DESKTOP-PPV5M0R:~/Lab09$ git commit -S -m "fix(lab09): remediate SAST and DAST findings"
[main b38becd] fix(lab09): remediate SAST and DAST findings
 5 files changed, 158 insertions(+), 63 deletions(-)
 create mode 100644 .env.example
svepodd@DESKTOP-PPV5M0R:~/Lab09$ git push origin main
Enumerating objects: 14, done.
Counting objects: 100% (14/14), done.
Delta compression using up to 22 threads
Compressing objects: 100% (8/8), done.
Writing objects: 100% (8/8), 5.46 KiB | 5.46 MiB/s, done.
Total 8 (delta 0), reused 0 (delta 0), pack-reused 0
To github.com:svepodd/Lab09.git
   883948b..b38becd  main -> main
```

На основании результатов сканеров (шаги 11–14) внесены исправления в `app/app.py`, `app/Dockerfile`, `app/requirements.txt` и `docker-compose.yml`.

**Исправления в `app/app.py` (устраняют находки Semgrep):**

| Находка (правило)                  | Было                                           | Стало                                                                        |
| ---------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------- |
| `py-sql-injection`                 | `query = f"...WHERE name = '{username}'"`      | параметризованный запрос `execute("...WHERE name = ?", (username,))`         |
| `py-command-injection` (`/ping`)   | `os.system(f"ping -c 1 {host}")`               | валидация `host` как IP + `subprocess.run(["ping","-c","1",host])` без shell |
| `py-command-injection` (`/backup`) | `subprocess.call(["sh","-c", f"...{target}"])` | фиксированное имя файла, без shell и без пользовательского ввода             |
| `py-insecure-deserialization`      | `pickle.loads(...)`                            | `json.loads(...)` - не выполняет код                                         |
| `py-unsafe-eval`                   | `eval(expr)`                                   | ограниченный AST-вычислитель `_safe_calc` (только арифметика)                |
| `py-hardcoded-credentials`         | `DB_PASSWORD = "SuperSecret123"`               | чтение из переменных окружения `os.environ`                                  |
| `py-flask-debug-enabled`           | `app.config["DEBUG"] = True`                   | управляется env, по умолчанию `False`                                        |
| path traversal (`/read`)           | `open(request.args.get("path"))`               | чтение только внутри `SAFE_READ_DIR` с проверкой пути                        |

Дополнительно: удалён debug-эндпоинт, раскрывавший переменные окружения; добавлены security-заголовки (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`) и убрана версия из заголовка `Server` - это устраняет находки DAST (ZAP 10038, 10020, 10021, 10036); пользовательский ввод в HTML экранируется через `markupsafe.escape` (защита от XSS).

**Исправления в `app/Dockerfile` (устраняют находки Checkov):**
- `CKV_DOCKER_3`: добавлен непривилегированный пользователь (`adduser appuser` + `USER appuser`) - контейнер больше не работает под root;
- `CKV_DOCKER_2`: добавлена инструкция `HEALTHCHECK`.

**Исправления в `app/requirements.txt` (устраняют находки SCA и Trivy):** Версии пакетов подняты до закрывающих найденные CVE (Flask 3.0.3, Werkzeug 3.0.6, Jinja2 3.1.5, PyYAML 6.0.2 и др.). Неиспользуемые приложением тяжёлые зависимости (Django, paramiko, SQLAlchemy, requests) удалены - именно они давали большинство критических CVE (Django 2.2 - 6 critical в Trivy; PyYAML 5.3.1 и certifi - critical 9.8 в SCA).

**Исправления в `docker-compose.yml`:**
Захардкоженный `DB_PASSWORD=SuperSecret123` удалён, секреты вынесены в файл `.env` (добавлен в `.gitignore` и не коммитится), debug по умолчанию выключен.

**Результат повторного прогона пайплайна:**

| Инструмент             | До исправлений     | После исправлений |
| ---------------------- | ------------------ | ----------------- |
| Semgrep (SAST)         | 8                  | 0                 |
| Checkov (SAST)         | 2 FAILED           | 0                 |
| Dependency-Check (SCA) | 8 (2 critical 9.8) | 0                 |
| OWASP ZAP (DAST)       | 18                 | 0                 |
| Trivy (Image scan)     | 77                 | 36                |
| **Critical суммарно**  | 9                  | 0                 |
| **Всего**              | 111                | 36                |

Все 36 оставшихся находок принадлежат **только Trivy** и относятся **исключительно к базовому образу Debian** (системные пакеты), а не к коду приложения или его Python-зависимостям:

- **`linux-libc-dev` - 27 находок** (заголовки ядра Linux);
- `libxml2`, `libxml2-dev`, `libncursesw6`, `libtinfo6`, `ncurses-*` - оставшиеся 9.

Большинство этих уязвимостей не имеют доступной версии-исправления (поле _fixed version_ пустое) - это известная особенность системных пакетов базового образа: их устранение находится в зоне ответственности сопровождающих образа Debian / Python, а не разработчика приложения.

- [x] 16. Измените `exit-code` Trivy и `fail_action` ZAP на `"1"` / `true` и убедитесь, что pipeline действительно блокируется при нахождении критических уязвимостей. Опишите в отчёте: что произошло, какой job упал, каков был exit code

```yaml
# В devsecops.yml — Trivy
exit-code: "1"

# В devsecops.yml — ZAP
fail_action: true
```

Меняем `exit-code` Trivy и `fail_action` ZAP на `"1"` / `true`:

```shell
svepodd@DESKTOP-PPV5M0R:~/Lab09/.github/workflows$ cat devsecops.yml | grep exit-code:
          exit-code: "1"
svepodd@DESKTOP-PPV5M0R:~/Lab09/.github/workflows$ cat devsecops.yml | grep fail_action:
          fail_action: true
```

**Что произошло при повторном прогоне:**

После push пайплайн запустился и заблокировался на quality gate. Упал job **`Build + Trivy Image Scan`**. Из лога видно, что Trivy корректно определил базовый образ (`Detected OS family="debian" version="13.5"`), просканировал 149 системных пакетов Debian и Python-зависимости, после чего завершился с ошибкой:

```
Error: Process completed with exit code 1.
```

После исправления зависимостей SCA проходит. Trivy же продолжает находить 36 HIGH-уязвимостей в базовом образе, и при `exit-code: "1"` именно они блокируют пайплайн.

Поскольку job DAST зависит от build-and-scan и был пропущен, блокирующий эффект `fail_action: true` в этом прогоне не проявился - пайплайн остановился раньше, на Trivy.

**Сравнение с предыдущим срабатыванием gate:** на прогоне до исправлений (шаг 15) блокировка происходила на этапе `SCA - Dependency-Check` из-за критических CVE в зависимостях (CVSS 9.8 в PyYAML и certifi). После исправления зависимостей SCA проходит. Trivy же продолжает находить 36 HIGH-уязвимостей в базовом образе, и при `exit-code: "1"` именно они блокируют пайплайн. Это демонстрирует, что quality gate работает на каждом уровне независимо.

**Вывод:** блокирующий quality gate функционирует корректно. При обнаружении уязвимостей заданного уровня критичности пайплайн прерывается с ненулевым кодом возврата (exit code 1), останавливая дальнейшее выполнение и не допуская «небезопасную» сборку до следующих этапов. Это и есть ключевой механизм автоматического контроля безопасности в CI/CD.

- [x] 17. Верните пороги в режим аудита (`exit-code: "0"`, `fail_action: false`), запустите полный пайплайн, скачайте артефакт `unified-report` и убедитесь, что HTML-отчёт корректно собирается

Отчет корректно собирается и находится по пути `Lab09/report/unified-report.html`.

- [x] 18. Делайте все коммиты на соответствующих шагах, отправляйте изменения в удалённый репозиторий
- [x] 19. Подготовьте отчёт `gist`

***
Copyright (c) 2026 Svetlana Poddoskina
