"use client";
import { useEffect, useState } from "react";
import EditableImage from "@/app/components/layout/EditableImage";
import Link from "next/link";
import Left from "@/app/components/icons/Left";
import MenuItemPriceProps from "@/app/components/layout/MenuItemPriceProps";
import { redirect, useParams } from "next/navigation";
import toast from "react-hot-toast";
import Header from "@/app/components/layout/Header";

export default function NewMenuItemPage(onSubmit,menuItem) {
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
 
	async function onSubmit(ev, data) {
        ev.preventDefault();
        const savingPromise = new Promise(async (resolve, reject) => {
            const response = await fetch('/api/menu-items', {
                method: 'POST',
                body: JSON.stringify(data),
                headers: { 'Content-Type': 'application/json' },
            });
            if (response.ok)
                resolve();
            else
                reject();
        });

        await toast.promise(savingPromise, {
            loading: 'Saving this Item',
            success: 'Item Saved',
            error: 'Error Occured',
        });

        setRedirectToItems(true);
    }
    if (redirectToItems) {
        return redirect('/menu-items');
    }


  return(
    <section>

    
    <Header />
    <div className="mt-8 max-w-4xl mx-auto">
        <form onSubmit={ev => onSubmit(ev, {image,name,description,basePrice,sizes,extraIngredientPrices,category})} 
            className="mt-8 max-w-2xl mx-auto">
            
        <h1 className="text-center justify-center text-primary text-4xl mb-4 uppercase">
                    menu items
                </h1>		
        
                <div className="max-w-md mx-auto mt-8">
                    <Link href={'/menu-items'} className="button">
                        <span>show all menu items</span>
                        <Left />
                    </Link>
                </div>
        <div className="mt-8 max-w-2xl mx-auto">
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
                        </div>                     
                    </div>
                </div>
            </div>    
        </form>
    </div>
</section>
  );
}