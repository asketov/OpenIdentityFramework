# OpenIdentityFramework.Host.Mvc

To build frontend

```bash
npm ci
npm run build
```

To run database

```bash
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=P@sSw0rd!" -p 1433:1433 -d --name oidfmssql --hostname oidfmssql mcr.microsoft.com/mssql/server:2022-latest
```

To stop and remove database

```bash
docker stop oidfmssql
docker rm oidfmssql
```

To add ConfigurationDbContext migration

```
dotnet ef migrations add InitialConfiguration -c ConfigurationDbContext -o DbContexts/Configuration/Migrations
```
