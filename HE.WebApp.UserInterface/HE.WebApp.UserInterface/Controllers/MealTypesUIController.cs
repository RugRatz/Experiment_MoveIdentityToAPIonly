using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using System.Web;
using System.Web.Mvc;
using HE.API.DbContexts;
using HE.API.Models;
using HE.WebApp.UserInterface.Models;

namespace HE.WebApp.UserInterface.Controllers
{
    public class MealTypesUIController : Controller
    {
        // GET: MealTypesModels
        public async Task<ActionResult> Welcome()
        {
            var mealTypesList = await WebApiService.Instance.GetAsync("api/MealTypes");
            return View("Welcome");
        }

        #region GET: MealTypesModels/Details/5
        //// GET: MealTypesModels/Details/5
        //public async Task<ActionResult> Details(int? id)
        //{
        //    if (id == null)
        //    {
        //        return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        //    }
        //    MealTypesModel mealTypesModel = await db.MealTypesModels.FindAsync(id);
        //    if (mealTypesModel == null)
        //    {
        //        return HttpNotFound();
        //    }
        //    return View(mealTypesModel);
        //}
        #endregion
            
        //// GET: MealTypesModels/Create
        //public ActionResult Create()
        //{
        //    return View();
        //}


        //// POST: MealTypesModels/Create
        //// To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        //// more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public async Task<ActionResult> Create([Bind(Include = "MealTypeID,Name,IsSystemDefault,DateCreatedUTC,LastUpdatedUTC")] MealTypesModel mealTypesModel)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        db.MealTypesModels.Add(mealTypesModel);
        //        await db.SaveChangesAsync();
        //        return RedirectToAction("Index");
        //    }

        //    return View(mealTypesModel);
        //}

        #region GET: MealTypesModels/Edit/5
        //// GET: MealTypesModels/Edit/5
        //public async Task<ActionResult> Edit(int? id)
        //{
        //    if (id == null)
        //    {
        //        return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        //    }
        //    MealTypesModel mealTypesModel = await db.MealTypesModels.FindAsync(id);
        //    if (mealTypesModel == null)
        //    {
        //        return HttpNotFound();
        //    }
        //    return View(mealTypesModel);
        //}
        #endregion

        #region POST: MealTypesModels/Edit/5
        //// POST: MealTypesModels/Edit/5
        //// To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        //// more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public async Task<ActionResult> Edit([Bind(Include = "MealTypeID,Name,IsSystemDefault,DateCreatedUTC,LastUpdatedUTC")] MealTypesModel mealTypesModel)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        db.Entry(mealTypesModel).State = EntityState.Modified;
        //        await db.SaveChangesAsync();
        //        return RedirectToAction("Index");
        //    }
        //    return View(mealTypesModel);
        //}
        #endregion

        #region GET: MealTypesModels/Delete/5
        //// GET: MealTypesModels/Delete/5
        //public async Task<ActionResult> Delete(int? id)
        //{
        //    if (id == null)
        //    {
        //        return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        //    }
        //    MealTypesModel mealTypesModel = await db.MealTypesModels.FindAsync(id);
        //    if (mealTypesModel == null)
        //    {
        //        return HttpNotFound();
        //    }
        //    return View(mealTypesModel);
        //}
        #endregion

        #region POST: MealTypesModels/Delete/5
        //// POST: MealTypesModels/Delete/5
        //[HttpPost, ActionName("Delete")]
        //[ValidateAntiForgeryToken]
        //public async Task<ActionResult> DeleteConfirmed(int id)
        //{
        //    MealTypesModel mealTypesModel = await db.MealTypesModels.FindAsync(id);
        //    db.MealTypesModels.Remove(mealTypesModel);
        //    await db.SaveChangesAsync();
        //    return RedirectToAction("Index");
        //}
        #endregion

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
