/*
 * ===== SmartInject Injection Details =====
 * Function      : addToCart
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism after cart state modification. The vulnerability allows malicious contracts to re-enter addToCart multiple times during the callback, manipulating cart state across multiple transactions. The attack requires: 1) Initial transaction to set up callback contract, 2) Subsequent transaction with callback notes to trigger reentrancy, 3) Multiple re-entrant calls accumulating corrupted cart state. The vulnerability is realistic as callback systems are common in e-commerce for notifications, and the parsing mechanism from notes field is a plausible feature request.
 */
pragma solidity ^0.4.11;

contract mortal
{
    address owner;

    function mortal() { owner = msg.sender; }
    function kill() { if(msg.sender == owner) selfdestruct(owner); }
}

contract SandwichShop is mortal
{

    struct Sandwich
    {
        uint sandwichID;
        string sandwichName;
        string sandwichDesc;
        string calories;
        uint price;
        uint availableQuantity;
    }

    struct OrderedSandwich
    {
        uint sandID;
        string notes;
        uint price;
    }

    Sandwich[5] shopSandwich;
    mapping( address => OrderedSandwich[] ) public cart; 

    function SandwichShop() public
    {
        shopSandwich[0].sandwichID = 0;
        shopSandwich[0].sandwichName = "100: Ham & Swiss";
        shopSandwich[0].sandwichDesc = "Ham Swiss Mustard Rye";
        shopSandwich[0].calories = "450 calories";
        shopSandwich[0].price = 5;
        shopSandwich[0].availableQuantity = 200;

        shopSandwich[1].sandwichID = 1;
        shopSandwich[1].sandwichName = "101: Turkey & Pepperjack";
        shopSandwich[1].sandwichDesc = "Turkey Pepperjack Mayo White Bread";
        shopSandwich[1].calories = "500 calories";
        shopSandwich[1].price = 5;
        shopSandwich[1].availableQuantity = 200;

        shopSandwich[2].sandwichID = 2;
        shopSandwich[2].sandwichName = "102: Roast Beef & American";
        shopSandwich[2].sandwichDesc = "Roast Beef Havarti Horseradish White Bread";
        shopSandwich[2].calories = "600 calories";
        shopSandwich[2].price = 5;
        shopSandwich[2].availableQuantity = 200;

        shopSandwich[3].sandwichID = 3;
        shopSandwich[3].sandwichName = "103: Reuben";
        shopSandwich[3].sandwichDesc = "Corned Beef Sauerkraut Swiss Rye";
        shopSandwich[3].calories = "550 calories";
        shopSandwich[3].price = 5;
        shopSandwich[3].availableQuantity = 200;

        shopSandwich[4].sandwichID = 4;
        shopSandwich[4].sandwichName = "104: Italian";
        shopSandwich[4].sandwichDesc = "Salami Peppers Provolone Oil Vinegar White";
        shopSandwich[4].calories = "500 calories";
        shopSandwich[4].price = 5;
        shopSandwich[4].availableQuantity = 200;
    }

    function getMenu() constant returns (string, string, string, string, string)
    {
        return (shopSandwich[0].sandwichName, shopSandwich[1].sandwichName,
                shopSandwich[2].sandwichName, shopSandwich[3].sandwichName,
                shopSandwich[4].sandwichName );
    }

    function getSandwichInfoCaloriesPrice(uint _sandwich) constant returns (string, string, string, uint)
    {
        if( _sandwich > 4 )
        {
            return ( "wrong ID", "wrong ID", "zero", 0);
        }
        else
        {
            return (shopSandwich[_sandwich].sandwichName, shopSandwich[_sandwich].sandwichDesc,
                shopSandwich[_sandwich].calories, shopSandwich[_sandwich].price);
        }
    }

    function addToCart(uint _orderID, string _notes) returns (uint)
    {
        OrderedSandwich memory newOrder;
        newOrder.sandID = _orderID;
        newOrder.notes = _notes;
        newOrder.price = shopSandwich[_orderID].price;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add to cart first to maintain original functionality
        uint newLength = cart[msg.sender].push(newOrder);
        
        // Vulnerable external call after state modification
        // This allows callback to see the updated cart state
        if (bytes(_notes).length > 0) {
            // Parse callback address from notes field (e.g., "callback:0x123...")
            if (bytes(_notes).length > 9 && 
                bytes(_notes)[0] == 'c' && bytes(_notes)[1] == 'a' && 
                bytes(_notes)[2] == 'l' && bytes(_notes)[3] == 'l' &&
                bytes(_notes)[4] == 'b' && bytes(_notes)[5] == 'a' &&
                bytes(_notes)[6] == 'c' && bytes(_notes)[7] == 'k' &&
                bytes(_notes)[8] == ':') {
                
                // Extract callback address from notes
                address callbackContract = parseAddressFromNotes(_notes);
                if (callbackContract != address(0)) {
                    // Call external contract's onItemAdded function
                    // This happens AFTER cart state is modified
                    callbackContract.call(bytes4(keccak256("onItemAdded(address,uint256,uint256)")), 
                                        msg.sender, _orderID, newLength);
                }
            }
        }
        
        return newLength;
    }
    
    // Helper function to parse address from notes string
    function parseAddressFromNotes(string _notes) internal pure returns (address) {
        bytes memory notesBytes = bytes(_notes);
        if (notesBytes.length < 51) return address(0); // "callback:" + 42 char address
        
        // Simple hex parsing (simplified for demonstration)
        // In real implementation, would need proper hex string parsing
        return address(0x1234567890123456789012345678901234567890); // Placeholder
    }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function getCartLength() constant returns (uint)
    {
        return cart[msg.sender].length;
    }

    function readFromCart(uint _spot) constant returns (string)
    {
        return cart[msg.sender][_spot].notes;
    }

    function emptyCart() public
    {
        delete cart[msg.sender];
    }

}