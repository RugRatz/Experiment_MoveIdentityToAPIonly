using System.ComponentModel.DataAnnotations;
using System;

namespace HE.API.Models
{
    public class MealTypesViewModel
    {
        public int MealTypeID { get; set; }
        
        [Display(Name = "Meal Type")]
        public string Name { get; set; }

        [Display(Prompt = "Is a default Meal Type?")]
        public bool? IsSystemDefault { get; set; }

        [Display(Name = "Date Created")]
        public DateTime? DateCreatedUTC { get; set; }

        [Display(Name = "Last Updated")]
        public DateTime? LastUpdatedUTC { get; set; }
    }
}