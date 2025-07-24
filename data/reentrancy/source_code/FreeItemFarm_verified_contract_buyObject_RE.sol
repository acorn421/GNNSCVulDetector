/*
 * ===== SmartInject Injection Details =====
 * Function      : buyObject
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `pendingPurchases` mapping to track accumulated purchase amounts and `purchaseActive` to track active purchase states across transactions.
 * 
 * 2. **External Call Before State Update**: Added a vulnerable external call to `_beneficiary.call.value(0)(bytes4(keccak256("confirmPurchase()")))` that occurs BEFORE the critical state update to `contract_balance`.
 * 
 * 3. **Stateful Accumulation**: The `pendingPurchases[_beneficiary] += msg.value` accumulates values across multiple transactions, creating persistent state that can be manipulated.
 * 
 * 4. **Reentrancy Window**: The external call creates a reentrancy window where an attacker can call `buyObject` again before the state is properly updated, allowing them to manipulate the accumulated pending purchases.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls `buyObject` with malicious contract address as `_beneficiary`, sends 1 ETH
 * - **Transaction 2**: Malicious contract's `confirmPurchase()` function re-enters `buyObject` with additional ETH
 * - **Transaction 3**: Due to reentrancy, `pendingPurchases` accumulates incorrectly while `contract_balance` is updated with inflated values
 * - **Transaction 4**: Attacker exploits the inconsistent state to extract excess funds
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability relies on the accumulation of `pendingPurchases` across calls
 * - State persistence between transactions is essential for the exploit
 * - The attacker needs separate transactions to build up the vulnerable state and then exploit it
 * - Single-transaction exploitation is prevented by the need to establish the malicious contract and trigger the confirmation callback sequence
 */
pragma solidity ^0.4.18;


contract ERC20Basic {
}

contract FreeItemFarm
{
    ERC20Basic public object;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingPurchases;
mapping(address => bool) public purchaseActive;
uint256 public contract_balance;

function buyObject(address _beneficiary) external payable {
    require(msg.value > 0, "Payment required");
    
    // Track pending purchase for beneficiary
    pendingPurchases[_beneficiary] += msg.value;
    
    // Mark purchase as active before external call
    purchaseActive[_beneficiary] = true;
    
    // External call to beneficiary for purchase confirmation - VULNERABLE
    // This allows reentrancy before state is properly updated
    if (_beneficiary.call.value(0)(bytes4(keccak256("confirmPurchase()")))) {
        // Beneficiary confirmed purchase
        // State update happens AFTER external call - VULNERABLE
        contract_balance += pendingPurchases[_beneficiary];
        
        // Only reset if purchase wasn't interrupted by reentrancy
        if (purchaseActive[_beneficiary]) {
            pendingPurchases[_beneficiary] = 0;
            purchaseActive[_beneficiary] = false;
        }
    } else {
        // If confirmation fails, leave pending purchase active
        // This creates persistent state across transactions
        purchaseActive[_beneficiary] = false;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}
}

interface Item_token
{
    function transfer(address to, uint256 value) external returns (bool);
}

library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

/*  In the event that the frontend goes down you will still be able to access the contract
    through myetherwallet.  You go to myetherwallet, select the contract tab, then copy paste in the address
    of the farming contract.  Then copy paste in the ABI and click access.  You will see the available functions 
    in the drop down below.

    Quick instructions for each function. List of addresses for token and shops found here.  http://ethercraft.info/index.php/Addresses 

    farmItem:  shop_address is the address of the item shop you want to farm.  buy_amount is the amount you want to buy.
    e.g. stone boots.  shop_address = 0xc5cE28De7675a3a4518F2F697249F1c90856d0F5, buy_amount = 100

    withdrawMultiTokens: takes in multiple token_addresses that you want to withdraw.  Token addresses can be found in the site above.
    e.g. token_address1, token_address2, token_address3.

    If you want to view the balance of a token you have in the contract select tokenInventory in the dropdown on myetherwallet.
    The first address box is the address you used to call the farm function from.
    The second address box is the address of the token you want to check.
    The result is the amount you have in the contract.*/   

contract FlexiFarmv2 is Ownable {
    using SafeMath for uint256;
    
    bool private reentrancy_lock = false;

    mapping(address => mapping(address => uint256)) public tokenInventory;
    mapping(address => address) public shops;

    uint256 public total_buy;
    uint256 public gas_amount;
      
    modifier nonReentrant() {
        require(!reentrancy_lock);
        reentrancy_lock = true;
        _;
        reentrancy_lock = false;
    }

   
    function set_Gas(uint256 gas_val) onlyOwner external{
      gas_amount = gas_val;
    }

    
    function set_Total(uint256 buy_val) onlyOwner external{
      total_buy = buy_val;
    }

    //associating each shop with a token to prevent anyone gaming the system.  users can view these themselves to ensure the shops match the tokens
    //if they want.  
    function set_Shops(address[] shop_addresses, address[] token_addresses) onlyOwner nonReentrant external
    {
      require (shop_addresses.length == token_addresses.length);       

      for(uint256 i = 0; i < shop_addresses.length; i++){        
          shops[shop_addresses[i]] = token_addresses[i];              
      } 
    }

    //populates contract with 1 of each farmable token to deal with storage creation gas cost

    function initialBuy(address[] shop_addresses) onlyOwner nonReentrant external
    {
      require (shop_addresses.length <= 15);       

      for(uint256 i = 0; i < shop_addresses.length; i++){        
          FreeItemFarm(shop_addresses[i]).buyObject(this);              
      } 
    }

    function farmItems(address[] shop_addresses, uint256[] buy_amounts) nonReentrant external
    {
      require(shop_addresses.length == buy_amounts.length);
      uint256 totals;
      for (uint256 j = 0; j < buy_amounts.length; j++){  
        totals+=buy_amounts[j];
        assert(totals >= buy_amounts[j]);
      }
      require(totals <= total_buy);     
      
      for (uint256 i = 0; i < buy_amounts.length; i++){
        farmSingle(shop_addresses[i], buy_amounts[i]);
      }
    }

    function farmSingle(address shop_address, uint256 buy_amount) private
    {   
      address token_address = shops[shop_address];
                               
      for (uint256 i = 0; i < buy_amount; i++) {
            require(shop_address.call.gas(26290).value(0)() == true);
      }
      tokenInventory[msg.sender][token_address] = tokenInventory[msg.sender][token_address].add(buy_amount);   
    } 

    function withdrawTokens(address[] token_addresses) nonReentrant external{
      for(uint256 i = 0; i < token_addresses.length; i++){
        withdrawToken(token_addresses[i]);
      }
    }

    function withdrawToken(address token_address) private {
        require(tokenInventory[msg.sender][token_address] > 0);
        uint256 tokenbal = tokenInventory[msg.sender][token_address].mul(1 ether);
        tokenInventory[msg.sender][token_address] = 0;
        Item_token(token_address).transfer(msg.sender, tokenbal);        
    }  

    //just in case the amount of gas per item exceeds 26290.
    function backupfarmItems(address[] shop_addresses, uint256[] buy_amounts) nonReentrant external
    {
      require(shop_addresses.length == buy_amounts.length);
      uint256 totals;
      for (uint256 j = 0; j < buy_amounts.length; j++){  
        totals=buy_amounts[j];
        assert(totals >= buy_amounts[j]);
      }
      require(totals <= total_buy);     
      
      for (uint256 i = 0; i < buy_amounts.length; i++){
        backupfarmSingle(shop_addresses[i], buy_amounts[i]);
      }
    }        
   
    function backupfarmSingle(address shop_address, uint256 buy_amount) private
    { 
      address token_address = shops[shop_address]; 
      for (uint256 i = 0; i < buy_amount; i++) {
            require(shop_address.call.gas(gas_amount).value(0)() == true);
      }
      tokenInventory[msg.sender][token_address] = tokenInventory[msg.sender][token_address].add(buy_amount); 
    } 
}