"use client";
import { useEffect, useState } from "react";
import { useProfile } from "../components/UseProfile";
import UserTabs from "../components/layout/UserTabs";
import Link from "next/link";
import Header from "@/app/components/layout/Header";
import Image from "next/image";
import { useSession } from 'next-auth/react';
import SectionHeaders from "../components/layout/SectionHeaders";

export default function UsersPage(){
    const session = useSession();
    const [users, setUsers] = useState([]);
    const {loading, data} = useProfile();
    const [image, setImage] = useState('');
    const {status} = session;

    useEffect(() => {
        fetch('/api/users').then(response => {
            response.json().then(users =>{
                setUsers(users);
            });
        })
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
            return 'loading user info';
        }
        if (!data.admin) {
            return 'not an admin';
        }
    
    return (
        <section>
            <Header />
            <div className="mt-8 max-w-4xl mx-auto">
            <div className="text-center justify-center text-primary text-4xl mb-4 uppercase">
            <SectionHeaders mainHeader={'User'} />
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
                            <div className="mt-8 w-3/5">
                                {users?.length > 0 && users.map(user => (
                                    <div key={user._id} className="bg-gray-200 rounded-lg mb-2 p-1 px-4 items-center gap-4 flex">
                                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 grow">
                                            <div className="text-gray-700">
                                                {!!user.name && (<span>{user.name}</span>)}
                                                {!user.name && (<span className="italic">No name</span>)}
                                            </div>
                                            <span className="text-gray-400">{user.email}</span>
                                        </div>
                                        <div>
                                            <Link className="button" href={'/users/'+user._id}>Edit</Link>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        
                    </div>
                </div>
            </div>      
        </section>
    );
}