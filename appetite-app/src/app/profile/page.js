'use client';
import { useSession } from "next-auth/react";
import { redirect } from "next/navigation";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import UserFrom from "@/app/components/layout/UserForm";
import Header from "@/app/components/layout/Header";
import SectionHeaders from "../components/layout/SectionHeaders";


export default function ProfilePage() {
    const [user, setUser] = useState(null);
    const session = useSession();
    const [isAdmin, setIsAdmin] = useState(false);
    const [profileFetched, setProfileFetched] = useState(false);
    const {status} = session;

    useEffect(() => {
        if (status === 'authenticated') {
            fetch('/api/profile').then(response => {
                response.json().then(data => {
                    setUser(data);
                    setIsAdmin(data.admin);
                    setProfileFetched(true);
                })
            });
        }
    }, [status, session]);


    async function handleProfileInfoUpdate(ev, data) {
        ev.preventDefault();

        const savingPromise = new Promise(async (resolve, reject) => {
            const response = await fetch('/api/profile', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
        });
        if (response.ok) 
        resolve() 
        else
        reject();
    });
    await toast.promise(savingPromise, {  
        loading: 'Saving...',
        success: 'Profile Saved!',
        error: 'Error',
    });
}
    if (status === 'loading' || !profileFetched) {
        return 'loading...'
    }

    if (status === 'unauthenticated'){
        return redirect('/login');
    }
    return(
        <section>
            <Header />
            <div className="mt-8 max-w-4xl mx-auto">
                <div className="text-center justify-center text-primary text-4xl mb-4 uppercase">
                    <SectionHeaders mainHeader={'Profile'} />
                </div>
                <div>
                    <UserFrom user={user} onSave={handleProfileInfoUpdate} />
                </div>
            </div>
        </section>
    );
}
