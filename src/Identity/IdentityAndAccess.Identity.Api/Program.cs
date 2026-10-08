using IdentityAndAccess.Identity.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.AddApiServices();

var app = builder.Build();

app.UseApi();

app.Run();
