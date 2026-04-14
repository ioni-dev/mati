module MyApp.Db.Client where

data Client = Client
  { clientDsn :: String
  }

newClient :: Client
newClient = Client "localhost:5432"
