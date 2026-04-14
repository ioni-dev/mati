module Main where

import MyApp.Auth.UserService
import MyApp.Db.Client

main :: IO ()
main = do
  let db = newClient
  let user = createUser "admin" db
  putStrLn (show user)
