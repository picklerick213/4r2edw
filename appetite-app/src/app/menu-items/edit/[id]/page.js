'use client';
import { useProfile } from "@/app/components/UseProfile";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import Link from "next/link";
import Left from "@/app/components/icons/Left";
import {redirect, useParams} from "next/navigation";
import MenuItemForm from "@/app/components/layout/MenuItemForm";
import DeleteButton from "@/app/components/DeleteButton";
import Header from "@/app/components/layout/Header";

export default function EditMenuItemPage() {

    const {id} = useParams();
    const [menuItem, setMenuItem] = useState(null);
    const [redirectToItems, setRedirectToItems] = useState(false);
    const {loading, data} = useProfile();

    useEffect(() => {
        fetch('/api/menu-items').then(res => {
            res.json().then(items => {
                const item = items.find(i => i._id === id);
                setMenuItem(item);
            });
        })
    }, []);

    async function handleFormSubmit(ev, data) {
        ev.preventDefault();
        data = {...data, _id:id};
        const savingPromise = new Promise(async (resolve, reject) => {
            const response = await fetch('/api/menu-items', {
                method: 'PUT',
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

    if (loading){
        return 'loading user info...';
    }
    if (!data.admin) {
        return 'Not an Admin';
    }
    return (
        <section>
            <Header />
            <div className="mt-8 max-w-4xl mx-auto">
                <h1 className="text-center justify-center text-primary text-4xl mb-4 uppercase">
                    menu items
                </h1>
                <div className="max-w-md mx-auto mt-8">
                    <Link href={'/menu-items'} className="button">
                        <span>show all menu items</span>
                        <Left />
                    </Link>
                </div>
                <MenuItemForm menuItem={menuItem} onSubmit={handleFormSubmit}/>
                <div className="delete">
                    <div className="grid ">  
                    </div>
                </div>
            </div>
        </section>
    );
}
