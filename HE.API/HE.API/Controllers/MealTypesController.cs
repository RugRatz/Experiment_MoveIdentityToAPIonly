using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Description;
using HE.Domain;
using HE.API.DbContexts;
using System.Collections.Generic;

namespace HE.API.Controllers
{
    public class MealTypesController : ApiController
    {
        private HE_IdentityDbContext db = new HE_IdentityDbContext();

        // GET: api/MealTypes
        public IQueryable<MealType> GetMealTypes()
        {
            return db.MealTypes;
        }

        // GET: api/MealTypes/5
        [ResponseType(typeof(MealType))]
        public async Task<IHttpActionResult> GetMealType(int id)
        {
            MealType mealType = await db.MealTypes.FindAsync(id);
            if (mealType == null)
            {
                return NotFound();
            }

            return Ok(mealType);
        }

        // PUT: api/MealTypes/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutMealType(int id, MealType mealType)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != mealType.MealTypeID)
            {
                return BadRequest();
            }

            db.Entry(mealType).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!MealTypeExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/MealTypes
        [ResponseType(typeof(MealType))]
        public async Task<IHttpActionResult> PostMealType(MealType mealType)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.MealTypes.Add(mealType);
            await db.SaveChangesAsync();

            return CreatedAtRoute("DefaultApi", new { id = mealType.MealTypeID }, mealType);
        }

        // DELETE: api/MealTypes/5
        [ResponseType(typeof(MealType))]
        public async Task<IHttpActionResult> DeleteMealType(int id)
        {
            MealType mealType = await db.MealTypes.FindAsync(id);
            if (mealType == null)
            {
                return NotFound();
            }

            db.MealTypes.Remove(mealType);
            await db.SaveChangesAsync();

            return Ok(mealType);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool MealTypeExists(int id)
        {
            return db.MealTypes.Count(e => e.MealTypeID == id) > 0;
        }
    }
}