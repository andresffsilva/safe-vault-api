namespace SafeVaultApi.Api.Models
{
    public class Users
    {
        public int? Id { get; set; }
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public string? Passwd { get; set; }
        public bool? IsAdmin { get; set; }
    }
}