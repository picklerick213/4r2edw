import { useEffect, useState } from "react";
import EditableImage from "./EditableImage";
import MenuItemPriceProps from "@/app/components/layout/MenuItemPriceProps";
import DeleteButton from "@/app/components/DeleteButton";
import { redirect, useParams } from "next/navigation";
import toast from "react-hot-toast";

export default function MenuItemForm({onSubmit,menuItem}) {
  const [image, setImage] = useState(menuItem?.image || '');
  const [name, setName] = useState(menuItem?.name || '');
  const [description, setDescription] = useState(menuItem?.description || '');
  const [basePrice, setBasePrice] = useState(menuItem?.basePrice || '');
  const [sizes, setSizes] = useState(menuItem?.sizes || []); 
  const [extraIngredientPrices, setExtraIngredientPrices] = useState(menuItem?.extraIngredientPrices || []);
  const [categories, setCategories] = useState([]);
  const [category, setCategory] = useState(menuItem?.category || '');
  const [redirectToItems, setRedirectToItems] = useState(false);
  const {id} = useParams();

    useEffect(() => {
      fetch('/api/categories').then(res => {
        res.json().then(categories => {
          setCategories(categories);
        })
      })
  }, []);

    async function handleDeleteClick() {
      const promise = new Promise(async (resolve, reject) => {
          const res = await fetch('/api/menu-items?_id='+id, {
              method: 'DELETE',
          });
          if (res.ok)
          resolve();
          else
          reject();
      });
      await toast.promise(promise, {
          loading: 'Deleting',
          success: 'Deleted',
          error: 'Error Oucured',
      });
      setRedirectToItems(true);
      }

      if (redirectToItems) {
          return redirect('/menu-items');
      }


  return(

    <form onSubmit={ev => onSubmit(ev, {image,name,description,basePrice,sizes,extraIngredientPrices,category})} 
          className="mt-8 max-w-2xl mx-auto">
      <div
        className="grid items-start gap-4"
        style={{gridTemplateColumns: '0.3fr 0.7fr'}}>
          <div>
            <EditableImage link={image} setLink={setImage}/>
          </div>

        <div className="grow">
            <label>Item name</label>   
            <input type="text" value={name} onChange={ev => setName(ev.target.value)}/>

            <label>description</label>   
            <input type="text" value={description} onChange={ev => setDescription(ev.target.value)}/>

            <label>Category</label>
              <select value={category} onChange={ev => setCategory(ev.target.value)}>
                {categories?.length > 0 && categories.map(c =>(
                  <option key={c._id} value={c._id}>{c.name}</option>
                ))}
              </select>

            <label>Base Price</label>   
            <input type="text" value={basePrice} onChange={ev => setBasePrice(ev.target.value)}/>
              
              <MenuItemPriceProps name={'Sizes'} 
                                  addLabel={'Add Item Size'} 
                                  props={sizes} 
                                  setProps={setSizes} />
              <MenuItemPriceProps name={'Extra ingredients'} 
                                  addLabel={'Add Indgredients Prices'}
                                  props={extraIngredientPrices}
                                  setProps={setExtraIngredientPrices}/>
            <div className="flex gap-1">
              <button className="mb-2" type="submit">Save</button>
              <DeleteButton label="" onDelete={handleDeleteClick}/>
            </div>                     
            
        </div>
      </div>
    </form>
  );
}