"use client";
import { useProfile } from "@/app/components/UseProfile";
import Header from "@/app/components/layout/Header";
import UserForm from "@/app/components/layout/UserForm";
import UserTabs from "@/app/components/layout/UserTabs";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import Link from "next/link";


export default function EditUserPage() {
    const {loading, data} = useProfile();
    const  [user, setUser] = useState(null);
    const {id} = useParams();

    useEffect(() => {
        fetch('/api/profile?_id='+id).then(res => {
            res.json().then(user => {
                setUser(user);
            });
        })
    }, []);

    async function handleSaveButtonClick(ev, data){
        ev.preventDefault();
        const promise = new Promise(async(resolve, reject) => {
            const res = await fetch('/api/profile', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({...data,_id:id}),
            });
            if (res.ok) 
            resolve();
            else
            reject();
        });
        
        await toast.promise(promise, {
            loading: 'saving user...',
            success: 'user saved',
            error: 'an error occured'
        })
    }

    if (loading) {
        return 'loading user info';
    }
    if (!data.admin) {
        return 'not an admin';
    }

    return(
        <section>
            <Header />
            <div className="mt-8 mx-auto max-w-4xl">
                <h1 className="text-center justify-center text-primary text-4xl mb-4 uppercase">Users</h1>
                    <div className='mt-8 w-3/5 mx-auto'>
                        <Link className='button flex' href={'/users'}>
                            <span>Back to Users</span>
                        </Link>
                    </div>
                <div className="mt-8">
                    <UserForm user={user} onSave={handleSaveButtonClick} />
                </div>
            </div>
        </section>
    );
}