package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/suite"

	"astral--praktika-autotests/internal/fork"
)

// SetupSuite bootstraps suite dependencies
type KeyMasterSuite struct {
	suite.Suite

	AccessToken            string
	DatabaseUri            string
	Key                    string
	KeyMasterBinaryPath    string
	KeyMasterServerAddress string
	KeyMasterProcess       *fork.BackgroundProcess
	Host                   string
	Port                   string
	RefreshToken           string
}

// SetupSuite bootstraps suite dependencies
func (suite *KeyMasterSuite) SetupSuite() {
	suite.Host = "127.0.0.1"
	suite.Port = "8083"
	suite.KeyMasterServerAddress = "http://" + suite.Host + ":" + suite.Port
	suite.KeyMasterBinaryPath = "./keymaster"
	suite.DatabaseUri = "postgres://user:1234567890qwerty@localhost:5432/astral"
}

func (suite *KeyMasterSuite) serviceUp() {

	{
		args := []string{
			"--d=" + suite.DatabaseUri,
			"--a=" + suite.Host + ":" + suite.Port}

		p := fork.NewBackgroundProcess(context.Background(), suite.KeyMasterBinaryPath,
			fork.WithArgs(args...),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := p.Start(ctx)
		if err != nil {
			suite.T().Errorf("Невозможно запустить процесс командой %s: %s. Агументы запуска: %+v", p, err, args)

			return
		}

		port := suite.Port
		err = p.WaitPort(ctx, "tcp", port)
		if err != nil {
			suite.T().Errorf("Не удалось дождаться пока порт %s станет доступен для запроса: %s", port, err)

			return
		}

		suite.KeyMasterProcess = p
	}
}

func (suite *KeyMasterSuite) serviceStop() {
	if suite.KeyMasterProcess == nil {
		return
	}

	exitCode, err := suite.KeyMasterProcess.Stop(syscall.SIGINT, syscall.SIGKILL)
	if err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return
		}
		suite.T().Logf("Не удалось остановить процесс с помощью сигнала ОС: %s", err)

		return
	}

	if exitCode > 0 {
		suite.T().Logf("Процесс завершился с не нулевым статусом %d", exitCode)
	}

	// try to read stdout/stderr
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out := suite.KeyMasterProcess.Stderr(ctx)
	if len(out) > 0 {
		suite.T().Logf("Получен STDERR лог процесса:\n\n%s", string(out))
	}
	out = suite.KeyMasterProcess.Stdout(ctx)
	if len(out) > 0 {
		suite.T().Logf("Получен STDOUT лог процесса:\n\n%s", string(out))
	}
}

func (suite *KeyMasterSuite) TearDownSuite() {
	suite.serviceStop()
}

func (suite *KeyMasterSuite) TestKeyMaster() {
	suite.serviceUp()
	httpc := resty.New()
	suite.Run("register user-new", func() {
		var result Tokens
		body := `{"login":"user1", "password":"987234kj4"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetResult(&result).
			SetBody(body)

		//var value int64
		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/register")

		suite.AccessToken = result.AccessToken
		suite.RefreshToken = result.RefreshToken
		dumpErr := suite.Assert().NoError(err, "Ошибка при попытке зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("register user-duplicate", func() {
		body := `{"login":"user1", "password":"987234kj4"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetBody(body)

		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/register")
		dumpErr := suite.Assert().NoError(err, "Ошибка при повторно зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusInternalServerError, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("login: user-ok pwd-ok", func() {
		var result Tokens

		body := `{"login":"user1", "password":"987234kj4"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetResult(&result).
			SetBody(body)

		//var value int64

		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/login")
		dumpErr := suite.Assert().NoError(err, "Ошибка при попытке входа пользователя")

		suite.AccessToken = result.AccessToken
		suite.RefreshToken = result.RefreshToken

		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("login: user-bad", func() {
		body := `{"login":"sdfdfg", "password":"987234kj4"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetBody(body)

		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/login")
		dumpErr := suite.Assert().NoError(err, "Ошибка при попытке входа пользователя")

		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnauthorized, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("login: user-ok pwd-bad ", func() {
		body := `{"login":"user1", "password":"98798jkj"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetBody(body)

		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/login")
		dumpErr := suite.Assert().NoError(err, "Ошибка при попытке входа пользователя")

		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnauthorized, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("refresh token-ok", func() {
		req := httpc.R().
			SetHeader("Content-Type", "application/json")

		//var value int64
		body := `{"Token":"` + suite.RefreshToken + `"}`
		resp, err := req.SetBody(body).Post(suite.KeyMasterServerAddress + "/api/user/refresh")
		dumpErr := suite.Assert().NoError(err, "Ошибка при повторно зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("refresh token-bad", func() {
		badToken := "9879532k4hjl43jkh53245i3uy93wgvd.0gdsgjh.sagfdgsagdf"

		body := `{"Token":"` + badToken + `"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetBody(body)

		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/refresh")
		dumpErr := suite.Assert().NoError(err, "Ошибка при повторно зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnauthorized, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("get key-ok", func() {
		var result Key
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret")

		suite.Key = result.Key

		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("use key-ok", func() {
		var result Secret
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret/" + suite.Key)

		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().NotEmpty(result.Secret)
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("use key-bad", func() {
		var result Secret
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		wrongKey := "uyYIUUD8792"
		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret/" + wrongKey)

		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnprocessableEntity, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("use key-exceed attempts", func() {
		var result Secret
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		for i := 1; i <= 2; i++ {
			_, _ = req.Get(suite.KeyMasterServerAddress + "/api/user/secret/" + suite.Key)
		}
		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret/" + suite.Key)
		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().NotEmpty(result.Secret)
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusNotAcceptable, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.serviceStop()
}
func (suite *KeyMasterSuite) TestSecretExpiration() {
	if err := os.Setenv("EXPIRATION_PERIOD", "1s"); err != nil {
	}
	suite.serviceUp()
	httpc := resty.New()
	suite.Run("register user-new", func() {
		var result Tokens
		body := `{"login":"user1", "password":"987234kj4"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetResult(&result).
			SetBody(body)

		//var value int64
		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/register")

		suite.AccessToken = result.AccessToken
		suite.RefreshToken = result.RefreshToken
		dumpErr := suite.Assert().NoError(err, "Ошибка при попытке зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("get key-ok", func() {
		var result Key
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret")

		suite.Key = result.Key

		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("use key-expired", func() {
		var result Secret
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		time.Sleep(2 * time.Second)

		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret/" + suite.Key)
		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().Empty(result.Secret)
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnauthorized, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.serviceStop()
}
func (suite *KeyMasterSuite) TestRefreshTokenExpiration() {
	if err := os.Setenv("REFRESH_TOKEN_TTL", "5s"); err != nil {
	}
	if err := os.Setenv("ACCESS_TOKEN_TTL", "1s"); err != nil {
	}
	suite.serviceUp()
	httpc := resty.New()
	suite.Run("register user-new", func() {
		var result Tokens
		body := `{"login":"user1", "password":"987234kj4"}`

		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetResult(&result).
			SetBody(body)

		//var value int64
		resp, err := req.Post(suite.KeyMasterServerAddress + "/api/user/register")

		suite.AccessToken = result.AccessToken
		suite.RefreshToken = result.RefreshToken

		dumpErr := suite.Assert().NoError(err, "Ошибка при попытке зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("get key-ok", func() {
		var result Key
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret")

		suite.Key = result.Key

		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	time.Sleep(2 * time.Second)
	suite.Run("use key-ok access-expired", func() {
		var result Secret
		req := httpc.R().
			SetHeader("Content-Type", "plain/text").
			SetHeader("Authorization", suite.AccessToken).
			SetResult(&result)

		resp, err := req.Get(suite.KeyMasterServerAddress + "/api/user/secret/" + suite.Key)

		dumpErr := suite.Assert().NoError(err, "Ошибка при получении ключа")
		dumpErr = dumpErr && suite.Assert().Empty(result.Secret)
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnauthorized, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.Run("refresh refresh-ok", func() {
		var result Tokens
		req := httpc.R().
			SetHeader("Content-Type", "application/json").
			SetResult(&result)
		body := `{"Token":"` + suite.RefreshToken + `"}`
		resp, err := req.SetBody(body).Post(suite.KeyMasterServerAddress + "/api/user/refresh")

		suite.AccessToken = result.AccessToken
		suite.RefreshToken = result.RefreshToken

		dumpErr := suite.Assert().NoError(err, "Ошибка при повторно зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusOK, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	time.Sleep(6 * time.Second)
	suite.Run("refresh refresh-expired", func() {
		req := httpc.R().
			SetHeader("Content-Type", "application/json")
		body := `{"Token":"` + suite.RefreshToken + `"}`
		resp, err := req.SetBody(body).Post(suite.KeyMasterServerAddress + "/api/user/refresh")
		dumpErr := suite.Assert().NoError(err, "Ошибка при повторно зарегистрировать пользователя")
		dumpErr = dumpErr && suite.Assert().Equalf(http.StatusUnauthorized, resp.StatusCode(),
			"Несоответствие статус кода ответа ожидаемому в хендлере %q: %q ", req.Method, req.URL)

		if !dumpErr {
			dump := dumpRequestShort(req.RawRequest, true)
			suite.T().Logf("Оригинальный запрос:\n\n%s", dump)
		}
	})
	suite.serviceStop()
}
