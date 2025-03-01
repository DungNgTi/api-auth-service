FROM mcr.microsoft.com/dotnet/aspnet:8.0-preview AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0-preview AS build
WORKDIR /src
COPY ["api-auth-service/api-auth-service.csproj", "./"]
RUN dotnet restore "api-auth-service.csproj"

COPY api-auth-service/ .  
RUN dotnet build "api-auth-service.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "api-auth-service.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "api-auth-service.dll"]