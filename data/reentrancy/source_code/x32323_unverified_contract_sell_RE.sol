/*
 * ===== SmartInject Injection Details =====
 * Function      : sell
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding pendingSales tracking that persists across transactions. The vulnerability requires multiple function calls to exploit:
 * 
 * 1. **State Variables Added** (assumed to be declared elsewhere in contract):
 *    - `mapping(address => uint256) public pendingSales` - tracks pending sales amounts
 *    - `mapping(address => uint256) public lastSaleTime` - tracks when sale was initiated
 *    - `uint256 public saleDelay = 1 hours` - delay before pending sales can be cleared
 * 
 * 2. **Multi-Transaction Exploitation Pattern**:
 *    - Transaction 1: User calls sell() → pendingSales is set, balances updated, transfer occurs, but pendingSales not cleared due to time delay
 *    - During transfer in Transaction 1: Attacker's fallback function can call sell() again while pendingSales still shows previous amount
 *    - Transaction 2: Second call to sell() sees inconsistent state where pendingSales contains old value but balances were already updated
 *    - This creates a window where the attacker can manipulate the pending state across multiple transactions
 * 
 * 3. **Why Multiple Transactions Are Required**:
 *    - The pendingSales state persists between transactions due to the time delay mechanism
 *    - The vulnerability cannot be exploited in a single transaction because the state inconsistency only becomes exploitable when combined with the persistent pendingSales tracking
 *    - An attacker needs to accumulate state through multiple calls to create exploitable conditions
 * 
 * 4. **Realistic Business Logic**:
 *    - The pending sales tracking appears to be a legitimate feature for tracking ongoing sales
 *    - The time delay mechanism mimics real-world settlement delays
 *    - The vulnerability is subtle and would likely pass basic code review
 * 
 * The key vulnerability is that the external call (transfer) occurs before the pendingSales state is properly cleared, and the clearing depends on a time condition that can span multiple transactions, creating a stateful reentrancy opportunity.
 */
pragma solidity ^0.4.16;
contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}    

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract x32323 is owned{

//設定初始值//

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;
    mapping (address => bool) initialized;
    
    // VULNERABILITY SUPPORT STATE
    mapping(address => uint256) public pendingSales;
    mapping(address => uint256) public lastSaleTime;
    uint256 public saleDelay = 0; // Default, can be set for reentrancy sale window
    uint256 public minBalanceForAccounts;

    event FrozenFunds(address target, bool frozen);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Airdrop(address indexed to, uint256 value);

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }

    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 2;
    uint256 public totalSupply;
    uint256 public maxSupply = 2300000000;
    uint256 airdropAmount = 300;
    uint256 bonis = 100;
    uint256 totalairdrop = 3000;

//初始化//

    function TokenERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        initialSupply = maxSupply - totalairdrop;
        balanceOf[msg.sender] = initialSupply;
        totalSupply = initialSupply;
        initialized[msg.sender] = true;
        name = "測試15";
        symbol = "測試15";         
    }

    function initialize(address _address) internal returns (bool success) {
        if (totalSupply <= (maxSupply - airdropAmount) && !initialized[_address]) {
            initialized[_address] = true ;
            balanceOf[_address] += airdropAmount;
            totalSupply += airdropAmount;
            Airdrop(_address , airdropAmount);
        }
        return true;
    }
    
    function reward(address _address) internal returns (bool success) {
    if (totalSupply < maxSupply) {
            balanceOf[_address] += bonis;
            totalSupply += bonis;
            Airdrop(_address , bonis);
            return true;
    }
    }
//交易//

    function _transfer(address _from, address _to, uint _value) internal {
    require(!frozenAccount[_from]);
        require(_to != 0x0);

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);

        //uint previousBalances = balanceOf[_from] + balanceOf[_to];
       
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);

        //assert(balanceOf[_from] + balanceOf[_to] == previousBalances);

    initialize(_from);
    reward(_from);
    initialize(_to);
        
        
    }

    function transfer(address _to, uint256 _value) public {
        
    if(msg.sender.balance < minBalanceForAccounts)
            sell((minBalanceForAccounts - msg.sender.balance) / sellPrice);
        _transfer(msg.sender, _to, _value);
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

//販售//

    uint256 public sellPrice;
    uint256 public buyPrice;

    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner public {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    function buy() public payable returns (uint amount){
        amount = msg.value / buyPrice;                    // calculates the amount
        require(balanceOf[this] >= amount);               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        balanceOf[this] -= amount;                        // subtracts amount from seller's balance
        Transfer(this, msg.sender, amount);               // execute an event reflecting the change
        return amount;                                    // ends function and returns
    }

    function sell(uint amount) public returns (uint revenue){
        require(balanceOf[msg.sender] >= amount);         // checks if the sender has enough to sell
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // New state tracking for multi-transaction vulnerability
        if (pendingSales[msg.sender] == 0) {
            pendingSales[msg.sender] = amount;
            lastSaleTime[msg.sender] = block.timestamp;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[this] += amount;                        // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                  // subtracts the amount from seller's balance
        revenue = amount * sellPrice;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call before clearing pending state (vulnerable pattern)
        msg.sender.transfer(revenue);                     // sends ether to the seller: VULNERABLE - state not cleared yet
        
        // State only cleared after external call in separate transaction path
        if (block.timestamp >= lastSaleTime[msg.sender] + saleDelay) {
            pendingSales[msg.sender] = 0;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, this, amount);               // executes an event reflecting on the change
        return revenue;                                   // ends function and returns
    }
    
    function setMinBalance(uint minimumBalanceInFinney) onlyOwner public {
         minBalanceForAccounts = minimumBalanceInFinney * 1 finney;
    }

}
