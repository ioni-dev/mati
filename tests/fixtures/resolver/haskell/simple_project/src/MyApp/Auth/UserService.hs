module MyApp.Auth.UserService where

import MyApp.Db.Client

data User = User
  { userName :: String
  , userId   :: Int
  }

createUser :: String -> Client -> User
createUser name _ = User name 1
