using IdentityAndAccess.Identity.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.AddApiServices();
// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();
app.UseApi();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
