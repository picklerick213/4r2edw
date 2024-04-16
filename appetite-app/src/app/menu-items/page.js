'use client';
import Link from 'next/link';
import {useProfile} from '../components/UseProfile';
import UserTabs from '../components/layout/UserTabs';
import Right from '../components/icons/Right';
import { useEffect, useState } from 'react';
import { useSession } from 'next-auth/react';
import Image from 'next/image';
import Header from "@/app/components/layout/Header";
import SectionHeaders from '../components/layout/SectionHeaders';



export default function MenuItemsPage(){
    const session = useSession();
    const [menuItems, setMenuItems] = useState([]);
    const {loading, data} = useProfile();
    const [image, setImage] = useState('');
    const {status} = session;

    useEffect(() => {
        fetch('/api/menu-items').then(res => {
            res.json().then(menuItems => {
                setMenuItems(menuItems);
            });
        });
    }, []);

    useEffect(() => {
        if (status === 'authenticated') {
            setImage(session.data.user.image);
            fetch('/api/menu-items').then(response => {
                response.json().then(data => {
                })
            });
        }
    }, [session]);

    if (loading) {
        return 'loading user info...';
    }
    if (!data.admin) {
        return 'Not an Admin.';
    }
    return (
        <section >
            <Header />
            <div className="mt-8 max-w-4xl mx-auto">
            <div className="text-center justify-center text-primary text-4xl mb-4 uppercase">
                <SectionHeaders mainHeader={'Menu Items'} />
            </div>
                <div>
                    <div className="flex justify-around">    
                            <div>
                                <div className="p-2 rounded-lg relative max-w-[120px] ">
                                {image && (
                                    <Image className="rounded-lg  mb-5" 
                                    src={image} width={250} height={250} alt={'avatar'} />
                                )}
                                    <div className='mt-8'>
                                        <UserTabs isAdmin={true} />
                                    </div>
                                </div>
                            </div>
                            <div className="border-r">

                            </div>
                        <div className="w-3/5">
                            <div className='mt-8'>
                                <Link className='button flex' href={'/menu-items/new'}>
                                    <span>Create New Menu Item</span>
                                <Right />
                                </Link>
                            </div>
                            <div>
                                <h2 className='text-sm text-gray-500 mt-8'> Edit Menu Item: </h2>
                                <div className='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2'>
                                {menuItems?.length > 0 && menuItems.map(item => (
                                    <Link 
                                    key={item._id}
                                    href={'/menu-items/edit/'+item._id} 
                                    className="bg-gray-300 p-4 rounded-lg text-center my-5 
                                    hover:bg-white transition-all hover:shadow-xl hover:shadow-black-300">
                                        <div className="relative">
                                            {item.image && (
                                                <Image className="rounded-md" 
                                                src={item.image} width={200} height={200} alt={'avatar'} />
                                            )}  
                                            {!item.image && (
                                                <div className="text-center bg-gray-400 p-4 text-gray-500 rounded-lg mb-1">
                                                    no image
                                                </div>
                                            )}
                                        </div>
                                        <div className='text-center'>
                                            {item.name}
                                        </div>
                                    </Link>
                                ))}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}

