"use client";
import { use, useEffect, useState } from "react";
import Header from "../components/layout/Header";
import SectionHeaders from "../components/layout/SectionHeaders";
import MenuItem from "../components/menu/MenuItem";

export default function MenuPage(){
    const [categories, setCategories] = useState([]);
    const [menuItems, setMenuItems] = useState([]);
    useEffect(() => {
        fetch('/api/categories').then(res => {
            res.json().then(categories => setCategories(categories))
        
        });
        fetch('/api/menu-items').then(res => {
            res.json().then(menuItems => setMenuItems(menuItems));
        })
    }, []);
    return(
        <section>
            <Header />
                <div className="mt-8 max-w-4xl mx-auto">
                    {categories?.length > 0 && categories.map(c => (
                        <div key={c._id}>
                            <div className="text-center">
                                <SectionHeaders mainHeader={c.name}/>
                            </div>
                            <div className="grid sm:grid-cols-3 gap-4 mt-4 mb-8">
                                {menuItems.filter(m => m.category === c._id).map(item => (
                                    <MenuItem key={item._id} {...item}/>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
        </section>
    )
}