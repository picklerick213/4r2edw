import { useContext, useState, useEffect } from "react";
import { CartContext, cartProductPrice } from "../components/AppContext";
import AddressInputs from "./layout/AddressInputs";
import {useParams} from "next/navigation";


export default function OrderPopUp(){
    const [order, setOrder] = useState();
    const [showConfirm, setShowConfirm] = useState(false);
    const {cartProducts,removeCartProduct} = useContext(CartContext);
    const {id} = useParams();

    useEffect(() => {
        if (typeof window.console !== "undefined") {
          if (window.location.href.includes('clear-cart=1')) {
            clearCart();
          }
        }
        if (id) {
          setLoadingOrder(true);
          fetch('/api/orders?_id='+id).then(res => {
            res.json().then(orderData => {
              setOrder(orderData);
              setLoadingOrder(false);
            });
          })
        }
      }, []);
    
    
    let subtotal=0;
        for (const p of cartProducts) {
           subtotal += cartProductPrice(p);
        }
    if (showConfirm) {
        
        return (
            <div className="fixed bg-black/70 inset-0 flex items-center h-full justify-center">
                <div className="bg-white p-4 rounded-lg">
                    <div className="bg-gray-100 p-4 rounded-lg">
                        <AddressInputs
                            disabled={true}
                            addressProps={order}
                        />
                    </div>
                    <div className="flex gap-2">
                        <button 
                        type="button" 
                        className="bg-green-700 hover:bg-green-600 text-white"
                        onClick={() => setShowConfirm(false)}>
                            Confirm Purchase
                        </button>
                    </div>
                </div>
            </div>
        );
    }
    return(
        <div className="max-w-2xl mx-auto">
            <button className="bg-primary text-white" type="button" onClick={() => setShowConfirm(true)}>
            pay ₱{subtotal+50}
            </button>
        </div>
        
    );
}
