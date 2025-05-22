using System.Net;
using System.Text.RegularExpressions;

namespace SafeVaultApi.Api.Utils
{
    public static class Validators
    {
        public static bool IsValidEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        public static string SanitizeInput(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            string sanitized = input.Trim();

            // Eliminar etiquetas <script> y otras HTML
            sanitized = Regex.Replace(sanitized, "<script.*?</script>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            sanitized = Regex.Replace(sanitized, "<.*?>", string.Empty);

            // Reemplazar patrones comunes de SQL injection
            sanitized = Regex.Replace(sanitized, @"(--|\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|XP_)\b|[';])", "", RegexOptions.IgnoreCase);

            // Encodear caracteres HTML especiales (&, <, >, ", ')
            sanitized = WebUtility.HtmlEncode(sanitized);

            return sanitized;
        }
    }
}