'use client'
import { useContext, useEffect, useState } from "react";
import Header from "../components/layout/Header";
import SectionHeaders from "../components/layout/SectionHeaders";
import { CartContext, cartProductPrice } from "../components/AppContext";
import Image from "next/image";
import Trash from "../components/icons/Trash";
import AddressInputs from "../components/layout/AddressInputs";
import { useProfile } from "../components/UseProfile";
import OrderPopUp from "@/app/components/OrderPopup";

export default  function CartPage({isAdmin}){
     const {cartProducts,removeCartProduct} = useContext(CartContext);
     const [address, setAddress] = useState({});
     const {data:profileData} = useProfile();

     


    useEffect(() => {
        if (profileData?.city){
            const {phone, streetAddress, city, postalCode, country} = profileData;
            const addressFromProfile = {
                phone, 
                streetAddress, 
                city, 
                postalCode, 
                country
            };
            setAddress(addressFromProfile);
        }
    }, [profileData]);


     let subtotal=0;
     for (const p of cartProducts) {
        subtotal += cartProductPrice(p);
     }
     function handleAddressChange(propName, value) {
        setAddress(prevAddress => ({...prevAddress, [propName]:value}));
     }
     if (cartProducts?.length === 0) {
        return (
          <section className=" text-center ">
            <Header />
            <p className="mt-60">Your shopping cart is empty 😔</p>
          </section>
        );
      }

    return(
        <section>
            <Header />
                <div className="mt-8 max-w-4xl mx-auto">
                    <div className="text-center">
                        <SectionHeaders mainHeader="Cart"/>
                    </div>
                    {!isAdmin && (
                                <div className="mt-8 grid md:gap-7 md:grid-cols-2">
                                <div>
                                    {cartProducts?.length === 0 && (
                                        <div className="text-center h-full w-full rounded-lg">
                                            <div className="pt-[11rem]">
                                            No products in your cart
                                            </div>
                                        </div>
                                    )}
                                    {cartProducts?.length > 0 && cartProducts.map((product, index) => (
                                        <div key={index} className="flex gap-4  border-b py-4 items-center">
                                            <div className="w-24">
                                            {product.image && (
                                                <Image width={240} height={240} src={product.image} alt={''} />
                                            )}
                                            {!product.image && (
                                                <div className="text-center bg-gray-200 p-4 text-gray-500 rounded-lg mb-1">
                                                    no image
                                                </div>
                                            )}
                                            </div>
                                            <div className="grow">
                                                <h3 className="font-semibold">
                                                    {product.name}
                                            </h3>
                                                {product.size && (
                                                    <div className="text-sm text-gray-700">
                                                        Size:<span>{product.size.name}</span>
                                                    </div>
                                                )}
                                                {product.extras?.length > 0 &&(
                                                    <div className="text-sm text-gray-500">
                                                        {product.extras.map(extra => (
                                                            <div>{extra.name} ₱{extra.price}</div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                            <div className="text-lg font-semibold">
                                                ₱{cartProductPrice(product)}
                                            </div>
                                            <div className="pl-2">
                                                <button 
                                                type="button"
                                                onClick={() => removeCartProduct(index)}
                                                className="p-2 bg-red-400 hover:bg-red-500 text-white">
                                                    <Trash />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                    <div className="py-2 flex justify-end items-center pr-16">
                                        <div className="text-gray-500">
                                            Subtotal:<br />
                                            Shipping fee:<br />
                                            Total:
                                        </div>
                                        <div className="text-lg font-semibold pl-2 text-right">
                                            ₱{subtotal}<br/>
                                            ₱50<br />
                                            ₱{subtotal + 50}
                                        </div>
                                    </div>
                                </div>

                                <div>
                                    <div className="bg-gray-200 p-4 rounded-lg">
                                        <h2>Checkout</h2>
                                        <form>
                                            <AddressInputs 
                                                addressProps={address} 
                                                setAddressProp={handleAddressChange}/>
                                            <button type="submit">Pay ${subtotal+5}</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        )} 
                       
                </div>
        </section>
    );
}
