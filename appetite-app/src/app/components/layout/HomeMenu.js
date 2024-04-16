'use client';
import { useEffect, useState } from 'react';
import MenuItem from '../menu/MenuItem';
import SectionHeaders from "@/app/components/layout/SectionHeaders";
import MenuItem2 from '../menu/MenuItem2';
import Footer from "@/app/components/layout/Footer";

export default function HomeMenu(){ 
    const [bestSellers, setBestSellers] = useState([]);
    useEffect(() => {
        fetch('/api/menu-items').then(res => {
            res.json().then(menuItems => {
                setBestSellers(menuItems.slice(-3));
            });
        });
    }, []);


    return (
    <section >
        
        <div className="max-w-5xl mx-auto p-4">
            <div className='mt-12'>
                <div className="text-center mt-12">
                    <SectionHeaders 
                    subHeader={'check out'}
                    mainHeader={'Our Best Sellers'}/>
                </div>
                <div className="grid md:grid-cols-3 gap-4">
                    {bestSellers?.length > 0 && bestSellers.map(item => (
                        <MenuItem key={item._id} {...item} />
                    ))}
                </div>
            </div>
        </div>
        <Footer />
    </section>
  );
}