"use client";
import EditableImage from "@/app/components/layout/EditableImage";
import UserTabs from "./UserTabs";
import { useEffect, useState } from "react";
import { useProfile } from "../UseProfile";
import { useSession } from "next-auth/react";
import AddressInputs from "@/app/components/layout/AddressInputs";

export default function UserForm({user,onSave}){
    const[userName, setUserName] = useState(user?.name || '');
    const [image, setImage] = useState(user?.image || '');
    const [phone, setPhone] = useState(user?.phone || '');
    const [streetAddress, setStreetAddress] = useState(user?.streetAddress || '');
    const [postalCode, setPostalCode] = useState(user?.postalCode || '');
    const [city, setCity] = useState(user?.city || '');
    const [country, setCountry] = useState(user?.country || '');
    const [admin, setAdmin] = useState(user?.admin || false);
    const [isAdmin, setIsAdmin] = useState(false);
    const session = useSession();
    const {status} = session;

function handleAddressChange(propName, value) {
    if (propName === 'phone') setPhone(value);
    if (propName === 'streetAddress') setStreetAddress(value);
    if (propName === 'postalCode') setPostalCode(value);
    if (propName === 'city') setCity(value);
    if (propName === 'country') setCountry(value);
}

    const {data:loggedInUserData} = useProfile();
    useEffect(() => {
        if (status === 'authenticated') {
            fetch('/api/profile').then(response => {
                response.json().then(data => {
                    setIsAdmin(data.admin);

                })
            });
        }
    }, [status, session]);

    return (
        <div className="flex justify-around">
                    <div>
                        <div className="p-2 rounded-lg relative max-w-[120px] ">
                            <EditableImage link={image} setLink={setImage}/>
                            <UserTabs isAdmin={isAdmin} />
                        </div>
                    </div>
                    <div className="border-r">

                    </div>
                    <div className="w-3/5">
                        <form className="grow mr-3" onSubmit={ev => onSave(ev, {name:userName,phone,image,streetAddress,city,country,admin,postalCode})}>
                        
                        <label>First and last name</label>
                        <input type="text" placeholder="first and last name"
                        value={userName} onChange={ev => setUserName(ev.target.value)}/>

                    <label>Email</label>
                            <input
                            type="email"
                            disabled={true}
                            value={user.email || ''}
                            placeholder={'email'}
                            />
                    <AddressInputs 
                    addressProps={{phone, streetAddress, postalCode, city, country,}}
                    setAddressProp={handleAddressChange}
                    />
                        {loggedInUserData.admin &&(
                            <div>
                                <label className="p-2 inline-flex items-center gap-2 mb-2" htmlFor="adminCb">
                                    <input id="adminCb" 
                                           type="checkbox" 
                                           className=""
                                           value={'1'}
                                           checked={admin}
                                           onChange={ev => setAdmin(ev.target.checked)}/>
                                    <span>Admin</span>
                                </label>
                            </div>
                        )}
                        <button type="submit">Save</button>
                    </form>
                    </div>
                </div>
    );
}