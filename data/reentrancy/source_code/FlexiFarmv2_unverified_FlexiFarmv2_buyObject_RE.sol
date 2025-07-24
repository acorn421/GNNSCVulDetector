/*
 * ===== SmartInject Injection Details =====
 * Function      : buyObject
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a refund mechanism that requires multiple transactions to exploit. The vulnerability involves:
 * 
 * 1. **State Accumulation Phase**: Users must call buyObject() multiple times to build up userBalances and purchaseCount state
 * 2. **Request Phase**: Users call requestRefund() to initiate the refund process with a time delay
 * 3. **Exploitation Phase**: Users call processRefund() which performs external call before state updates
 * 
 * **Multi-Transaction Exploitation Flow**:
 * - Transaction 1-N: Call buyObject() multiple times to accumulate balance and trigger loyalty bonus callbacks
 * - Transaction N+1: Call requestRefund() to initiate refund process
 * - Transaction N+2: After delay, call processRefund() which is vulnerable to reentrancy
 * 
 * **Key Vulnerability Features**:
 * - External calls in buyObject() loyalty bonus mechanism can be used to prepare attack contracts
 * - processRefund() performs external call before state updates (classic reentrancy)
 * - Requires persistent state (userBalances, refundRequested, refundRequestBlock) across multiple transactions
 * - Time delay ensures vulnerability cannot be exploited in single transaction
 * - Attacker can reenter processRefund() to drain multiple users' balances before state is updated
 * 
 * **Why Multiple Transactions Are Required**:
 * - Must accumulate balance through multiple buyObject() calls
 * - Must wait for refund delay period (5 blocks minimum)
 * - Cannot exploit the vulnerability atomically within a single transaction
 * - State persistence between transactions is essential for the attack vector
 */
pragma solidity ^0.4.18;

contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
}

contract FreeItemFarm
{
    ERC20Basic public object;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public userBalances;
    mapping(address => uint256) public purchaseCount;
    mapping(address => bool) public refundRequested;
    uint256 public constant REFUND_DELAY = 5; // blocks
    mapping(address => uint256) public refundRequestBlock;
    uint256 public contract_balance;

    function buyObject(address _beneficiary) external payable {
        require(msg.value > 0, "Must send payment");
        
        // Track user balance and purchase count
        userBalances[_beneficiary] += msg.value;
        purchaseCount[_beneficiary]++;
        
        // Update contract balance
        contract_balance += msg.value;
        
        // Distribute object token to beneficiary
        object.transfer(_beneficiary, 1 ether);
        
        // Special handling for users with multiple purchases
        if (purchaseCount[_beneficiary] >= 3) {
            // Callback to beneficiary for loyalty bonus (vulnerable external call)
            // In Solidity 0.4.x, no 'code' property. Use extcodesize instead.
            uint256 size;
            assembly { size := extcodesize(_beneficiary) }
            if (size > 0) {
                (bool success,) = _beneficiary.call(
                    abi.encodeWithSignature("onLoyaltyBonus(uint256)", purchaseCount[_beneficiary])
                );
                // Continue execution regardless of callback result
            }
        }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function requestRefund() external {
        require(userBalances[msg.sender] > 0, "No balance to refund");
        require(!refundRequested[msg.sender], "Refund already requested");
        
        refundRequested[msg.sender] = true;
        refundRequestBlock[msg.sender] = block.number;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function processRefund() external {
        require(refundRequested[msg.sender], "No refund requested");
        require(block.number >= refundRequestBlock[msg.sender] + REFUND_DELAY, "Refund delay not met");
        require(userBalances[msg.sender] > 0, "No balance to refund");
        
        uint256 refundAmount = userBalances[msg.sender];
        
        // Vulnerable: External call before state update
        (bool success,) = msg.sender.call.value(refundAmount)("");
        require(success, "Refund transfer failed");
        
        // State updates after external call - vulnerable to reentrancy
        userBalances[msg.sender] = 0;
        refundRequested[msg.sender] = false;
        contract_balance -= refundAmount;
        purchaseCount[msg.sender] = 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
  constructor() public {
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
