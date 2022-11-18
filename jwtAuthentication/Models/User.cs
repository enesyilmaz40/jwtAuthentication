using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace jwtAuthentication.Models
{
   public class User
    {
        [Key]
        public int Id { get; set; }
        public string NameSurname { get; set; }
        public string Email { get; set; }
        public string UserDescription { get; set; }
        public byte[] PaswordSalt { get; set; }
        public byte[] PasswordHash { get; set; }


    }
}
