using System;
using System.Threading.Tasks;
using Xunit;
using Serilog;
using Serilog.Extensions.Logging;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

using System.Collections.Generic;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using SecretClient = KeyVault.Secrets.Emulator.Rebel.Alliance.KeyVault.Secrets.Emulator.SecretClient;
using SecretProperties = KeyVault.Secrets.Emulator.Rebel.Alliance.KeyVault.Secrets.Emulator.SecretProperties;

namespace Tests.Rebel.Alliance.KeyVault.Secrets.Emulator
{
    public class SecretClientTests : IDisposable
    {
        private readonly ILogger<SecretClient> _logger;
        private readonly SecretClient _client;
        private readonly SecretClient _credentialClient;
        private readonly SecretClient _credentialClientWithOptions;

        public SecretClientTests(ITestOutputHelper output)
        {
            var logger = new LoggerConfiguration()
                .WriteTo.Console()
                .WriteTo.TestOutput(output)
                .CreateLogger();

            _logger = new SerilogLoggerFactory(logger).CreateLogger<SecretClient>();
            _client = new SecretClient(_logger);

            _credentialClient = new SecretClient(new Uri("http://fake.com"), new DefaultAzureCredential());
            _credentialClientWithOptions = new SecretClient(new Uri("http://fake.com"), new DefaultAzureCredential(), new SecretClientOptions());
        }

        [Fact]
        public async Task SetSecretAsync_ShouldStoreSecret()
        {
            var secretName = "TestSecret";
            var secretValue = "SecretValue";

            var secret = await _client.SetSecretAsync(secretName, secretValue);
            Assert.Equal(secretName, secret.Name);
            Assert.Equal(secretValue, secret.Value);
            
            var credentialSecret = await _credentialClient.SetSecretAsync(secretName, secretValue);
            Assert.Equal(secretName, credentialSecret.Name);
            Assert.Equal(secretValue, credentialSecret.Value);
            
            var credentialSecretWithOptions = await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            Assert.Equal(secretName, credentialSecretWithOptions.Name);
            Assert.Equal(secretValue, credentialSecretWithOptions.Value);
        }

        [Fact]
        public async Task GetSecretAsync_ShouldRetrieveSecret()
        {
            var secretName = "TestSecret";
            var secretValue = "SecretValue";

            await _client.SetSecretAsync(secretName, secretValue);
            var retrievedSecret = await _client.GetSecretAsync(secretName);
            Assert.Equal(secretName, retrievedSecret.Name);
            Assert.Equal(secretValue, retrievedSecret.Value);
            
            await _credentialClient.SetSecretAsync(secretName, secretValue);
            var credentialSecret = await _credentialClient.SetSecretAsync(secretName, secretValue);
            Assert.Equal(secretName, credentialSecret.Name);
            Assert.Equal(secretValue, credentialSecret.Value);
            
            await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            var credentialSecretWithOptions = await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            Assert.Equal(secretName, credentialSecretWithOptions.Name);
            Assert.Equal(secretValue, credentialSecretWithOptions.Value);
        }

        [Fact]
        public async Task SetSecretAsync_WithByteArray_ShouldStoreSecret()
        {
            var secretName = "ByteArraySecret";
            byte[] data = new byte[] { 1, 2, 3, 4, 5 };
            string base64String = Convert.ToBase64String(data);

            var secret = await _client.SetSecretAsync(secretName, base64String);
            Assert.Equal(secretName, secret.Name);
            Assert.Equal(base64String, secret.Value);
            
            var credentialSecret = await _credentialClient.SetSecretAsync(secretName, base64String);
            Assert.Equal(secretName, credentialSecret.Name);
            Assert.Equal(base64String, credentialSecret.Value);
            
            var credentialSecretWithOptions = await _credentialClientWithOptions.SetSecretAsync(secretName, base64String);
            Assert.Equal(secretName, credentialSecretWithOptions.Name);
            Assert.Equal(base64String, credentialSecretWithOptions.Value);
        }

        [Fact]
        public async Task GetSecretAsync_WithByteArray_ShouldRetrieveAndConvertSecret()
        {
            var secretName = "ByteArraySecret";
            byte[] originalData = new byte[] { 1, 2, 3, 4, 5 };
            string base64String = Convert.ToBase64String(originalData);

            await _client.SetSecretAsync(secretName, base64String);
            var retrievedSecret = await _client.GetSecretAsync(secretName);
            Assert.Equal(secretName, retrievedSecret.Name);
            Assert.Equal(base64String, retrievedSecret.Value);
            byte[] retrievedData = Convert.FromBase64String(retrievedSecret.Value);
            Assert.Equal(originalData, retrievedData);
            
            await _credentialClient.SetSecretAsync(secretName, base64String);
            var retrievedCredentialSecret = await _credentialClient.GetSecretAsync(secretName);
            Assert.Equal(secretName, retrievedCredentialSecret.Name);
            Assert.Equal(base64String, retrievedCredentialSecret.Value);
            byte[] retrievedCredentialData = Convert.FromBase64String(retrievedCredentialSecret.Value);
            Assert.Equal(originalData, retrievedCredentialData);
            
            await _credentialClientWithOptions.SetSecretAsync(secretName, base64String);
            var retrievedCredentialWithOptionsSecret = await _credentialClientWithOptions.GetSecretAsync(secretName);
            Assert.Equal(secretName, retrievedCredentialWithOptionsSecret.Name);
            Assert.Equal(base64String, retrievedCredentialWithOptionsSecret.Value);
            byte[] retrievedCredentialWithOptionsData = Convert.FromBase64String(retrievedCredentialWithOptionsSecret.Value);
            Assert.Equal(originalData, retrievedCredentialWithOptionsData);
        }

        [Fact]
        public async Task DeleteSecretAsync_ShouldMarkSecretAsDeleted()
        {
            var secretName = "TestSecretToDelete";
            var secretValue = "SecretValueToDelete";

            await _client.SetSecretAsync(secretName, secretValue);
            await _client.DeleteSecretAsync(secretName);
            var deletedSecret = await Assert.ThrowsAsync<KeyNotFoundException>(() => _client.GetSecretAsync(secretName));
            Assert.Equal($"Secret with name '{secretName}' not found.", deletedSecret.Message);
            
            await _credentialClient.SetSecretAsync(secretName, secretValue);
            await _credentialClient.DeleteSecretAsync(secretName);
            var deletedCedentialSecret = await Assert.ThrowsAsync<KeyNotFoundException>(() => _credentialClient.GetSecretAsync(secretName));
            Assert.Equal($"Secret with name '{secretName}' not found.", deletedCedentialSecret.Message);
            
            await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            await _credentialClientWithOptions.DeleteSecretAsync(secretName);
            var deletedCedentialWithOptionsSecret = await Assert.ThrowsAsync<KeyNotFoundException>(() => _credentialClientWithOptions.GetSecretAsync(secretName));
            Assert.Equal($"Secret with name '{secretName}' not found.", deletedCedentialWithOptionsSecret.Message);
        }

        [Fact]
        public async Task PurgeDeletedSecretAsync_ShouldRemoveSecretPermanently()
        {
            var secretName = "TestSecretToPurge";
            var secretValue = "SecretValueToPurge";

            await _client.SetSecretAsync(secretName, secretValue);
            await _client.DeleteSecretAsync(secretName);
            await _client.PurgeDeletedSecretAsync(secretName);
            var purgedSecret = await Assert.ThrowsAsync<KeyNotFoundException>(() => _client.RecoverDeletedSecretAsync(secretName));
            Assert.Equal($"Deleted secret with name '{secretName}' not found.", purgedSecret.Message);
            
            await _credentialClient.SetSecretAsync(secretName, secretValue);
            await _credentialClient.DeleteSecretAsync(secretName);
            await _credentialClient.PurgeDeletedSecretAsync(secretName);
            var purgedCredentialSecret = await Assert.ThrowsAsync<KeyNotFoundException>(() => _credentialClient.RecoverDeletedSecretAsync(secretName));
            Assert.Equal($"Deleted secret with name '{secretName}' not found.", purgedCredentialSecret.Message);
            
            await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            await _credentialClientWithOptions.DeleteSecretAsync(secretName);
            await _credentialClientWithOptions.PurgeDeletedSecretAsync(secretName);
            var purgedCredentialWithOptionsSecret = await Assert.ThrowsAsync<KeyNotFoundException>(() => _credentialClientWithOptions.RecoverDeletedSecretAsync(secretName));
            Assert.Equal($"Deleted secret with name '{secretName}' not found.", purgedCredentialWithOptionsSecret.Message);
        }

        [Fact]
        public async Task RecoverDeletedSecretAsync_ShouldRestoreDeletedSecret()
        {
            var secretName = "TestSecretToRecover";
            var secretValue = "SecretValueToRecover";

            await _client.SetSecretAsync(secretName, secretValue);
            await _client.DeleteSecretAsync(secretName);
            await _client.RecoverDeletedSecretAsync(secretName);
            var recoveredSecret = await _client.GetSecretAsync(secretName);
            Assert.Equal(secretName, recoveredSecret.Name);
            Assert.Equal(secretValue, recoveredSecret.Value);
            
            await _credentialClient.SetSecretAsync(secretName, secretValue);
            await _credentialClient.DeleteSecretAsync(secretName);
            await _credentialClient.RecoverDeletedSecretAsync(secretName);
            var recoveredCredentialSecret = await _credentialClient.GetSecretAsync(secretName);
            Assert.Equal(secretName, recoveredCredentialSecret.Name);
            Assert.Equal(secretValue, recoveredCredentialSecret.Value);
            
            await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            await _credentialClientWithOptions.DeleteSecretAsync(secretName);
            await _credentialClientWithOptions.RecoverDeletedSecretAsync(secretName);
            var recoveredCredentialWithOptionsSecret = await _credentialClientWithOptions.GetSecretAsync(secretName);
            Assert.Equal(secretName, recoveredCredentialWithOptionsSecret.Name);
            Assert.Equal(secretValue, recoveredCredentialWithOptionsSecret.Value);
        }

        [Fact]
        public async Task UpdateSecretPropertiesAsync_ShouldUpdateProperties()
        {
            var secretName = "TestSecretToUpdate";
            var secretValue = "SecretValueToUpdate";
            var properties = new SecretProperties
            {
                Name = secretName,
                ContentType = "text/plain",
                Tags = new Dictionary<string, string> { { "Environment", "Test" } }
            };

            await _client.SetSecretAsync(secretName, secretValue);
            await _client.UpdateSecretPropertiesAsync(properties);
            var updatedSecret = await _client.GetSecretAsync(secretName);
            Assert.Equal(secretName, updatedSecret.Properties.Name);
            Assert.Equal("text/plain", updatedSecret.Properties.ContentType);
            Assert.True(updatedSecret.Properties.Tags.ContainsKey("Environment"));
            Assert.Equal("Test", updatedSecret.Properties.Tags["Environment"]);
            
            await _credentialClient.SetSecretAsync(secretName, secretValue);
            await _credentialClient.UpdateSecretPropertiesAsync(properties);
            var updatedCredentialSecret = await _credentialClient.GetSecretAsync(secretName);
            Assert.Equal(secretName, updatedCredentialSecret.Properties.Name);
            Assert.Equal("text/plain", updatedCredentialSecret.Properties.ContentType);
            Assert.True(updatedCredentialSecret.Properties.Tags.ContainsKey("Environment"));
            Assert.Equal("Test", updatedCredentialSecret.Properties.Tags["Environment"]);
            
            await _credentialClientWithOptions.SetSecretAsync(secretName, secretValue);
            await _credentialClientWithOptions.UpdateSecretPropertiesAsync(properties);
            var updatedCredentialWithOptionsSecret = await _credentialClientWithOptions.GetSecretAsync(secretName);
            Assert.Equal(secretName, updatedCredentialWithOptionsSecret.Properties.Name);
            Assert.Equal("text/plain", updatedCredentialWithOptionsSecret.Properties.ContentType);
            Assert.True(updatedCredentialWithOptionsSecret.Properties.Tags.ContainsKey("Environment"));
            Assert.Equal("Test", updatedCredentialWithOptionsSecret.Properties.Tags["Environment"]);
        }

        public void Dispose()
        {
            // Cleanup logic if needed
        }
    }
}
