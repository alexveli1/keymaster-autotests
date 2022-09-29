# Запуск автотестов для системы "Мастер ключей"
## Подготовка
* clone repository
* в файле cma/keymaster_test.go в функции SetupTest установить переменные
- `suite.Host = "127.0.0.1"`
- `suite.Port = "8081"`
- `suite.DatabaseUri = "postgres://user:1234567890qwerty@localhost:5432/astral"`
## Запуск
* cmd/main_test.go --> TestKeyMaster
* исполняемый файл **keymaster** запускается автотестами самостоятельно


