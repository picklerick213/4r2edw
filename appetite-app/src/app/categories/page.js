'use client';
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import UserTabs from "../components/layout/UserTabs";
import {useProfile} from "../components/UseProfile";
import Image from "next/image";
import toast from "react-hot-toast";
import DeleteButton from "@/app/components/DeleteButton";
import Header from "../components/layout/Header";
import SectionHeaders from "../components/layout/SectionHeaders";

export default function CategoriesPage() {
    const session = useSession();
    const [categoryName, setCategoryName] = useState('');
    const [image, setImage] = useState('');
    const [categories, setCategories] = useState([]);
    const {loading:profileLoading, data:profileData} = useProfile();
    const [editedCategory, setEditedCategory] = useState(null);
    const {status} = session;

    useEffect(() => {
        if (status === 'authenticated') {
            setImage(session.data.user.image);
            fetch('/api/categories').then(response => {
                response.json().then(data => {
                })
            });
        }
    }, [session]);



    useEffect(() => {
        fetchCategories();
    }, []);

    function fetchCategories() {
        fetch('/api/categories').then(res => {
            res.json().then(categories => {
                setCategories(categories);
            });
        });
    }
    
    async function handleCategorySubmit(ev) {
        ev.preventDefault();
        const creationPromise = new Promise(async (resolve, reject) => {
            const data = {name:categoryName};
            if (editedCategory) {
                data._id = editedCategory._id;
            }
            const response = await fetch('/api/categories', {
                method: editedCategory ? 'PUT' : 'POST',
                headers:{ 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            setCategoryName('');
            fetchCategories();
            setEditedCategory(null);
            if (response.ok)
             resolve() 
            else 
            reject();
        });
        await toast.promise(creationPromise, {
            loading: editedCategory ? 'Updating Category' : 'Creating your new category...',
            success: editedCategory ? 'Category Updated' : 'Category Created',
            error: 'Creating Category Failed...',
        })
    }
    
    async function handleDeleteClick(_id){
        const promise = new Promise(async(resolve, reject) => {
            const response = await fetch('/api/categories?_id='+_id, {
                method: 'DELETE',
            });
            if (response.ok){
                resolve();
            } else {
                reject();
            }
        });

        
        await toast.promise(promise, {
            loading: 'Deleting',
            success: 'Deleted',
            error: 'Error Oucured',
        });

        fetchCategories();

    }

    if (profileLoading) {
        return 'loading user info...'
    }  

    if (!profileData.admin) {
        return 'not an admin'
    }
    return (
        <section  >
            <Header />
                <div className="mt-8 max-w-4xl mx-auto">
                    <div className="text-center uppercase justify-center text-primary text-4xl mb-4">
                        <SectionHeaders mainHeader={'Categories'} />
                    </div>
                <div>
                    <div className="flex justify-around">
                        <div className="p-2 rounded-lg relative max-w-[120px]">
                            {image && (
                                <Image className="rounded-lg  mb-5" 
                                src={image} width={250} height={250} alt={'avatar'} />
                            )}
                            
                                
                            <div className="mt-8">
                                <UserTabs isAdmin={true} />
                            </div>    
                        </div>

                            <div className="border-r">

                            </div>
                        
                            <div className="w-3/5">
                                <form className="grow " onSubmit={handleCategorySubmit}>
                                    <div className="flex gap-2 items-end">
                                        <div className="grow">
                                            <label className="text-nowrap">
                                                {editedCategory ? 'Update Category' : 'New Category Name'}
                                                {editedCategory && (
                                                    <>: <b>{editedCategory.name}</b> </>
                                                )}
                                            </label>
                                            <input className="mt-2" type="text" value={categoryName} 
                                            onChange={ev => setCategoryName(ev.target.value)} 
                                            
                                            />
                                        </div>
                                        <div className="flex gap-2 pb-2">
                                            <button type="submit" className="border ">
                                                {editedCategory ? 'Update' : 'Create'}
                                            </button>
                                            <button 
                                                type="button" 
                                                onClick={() => {setEditedCategory(null);setCategoryName('');
                                                }}>Cancel
                                            </button>
                                        </div>
                                    </div>
                                </form>
                                <div>
                                    <h2 className="mt-8 text-sm text-gray-500">Existing Categories</h2>
                                    {categories?.length > 0 && categories.map(c => (
                                        <div 
                                        key={c._id}
                                        className="bg-gray-200 rounded-lg p-2 px-4 flex gap-1 
                                        mb-1 items-center">
                                            <div className="grow">{c.name}</div>
                                            <div className="flex gap-1">
                                                <button type="button" 
                                                        onClick={() => {setEditedCategory(c); setCategoryName(c.name);
                                                    }}>Edit
                                                </button>
                                                <DeleteButton 
                                                className=""
                                                label={"Delete"} 
                                                onDelete={() => handleDeleteClick(c._id)}/>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
        </section>
    );
}