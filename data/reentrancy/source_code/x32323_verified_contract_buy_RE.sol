/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to user-controlled contracts that can accumulate bonus tokens across transactions. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: User calls buy() → callback is triggered → callback sets up state for future exploitation (bonusTokens mapping)
 * 2. **Transaction 2**: User calls buy() again → accumulated bonusTokens from previous transaction are applied → user receives more tokens than they paid for
 * 
 * The external call to IPurchaseCallback(msg.sender).onTokenPurchase() occurs before critical state updates, and the bonusTokens mapping persists between transactions, creating a multi-transaction exploitation path. An attacker can manipulate the bonusTokens state through the callback in one transaction, then exploit it in subsequent transactions.
 * 
 * Key vulnerability elements:
 * - External call to user-controlled contract before state updates
 * - Persistent state (bonusTokens mapping) that accumulates across transactions  
 * - Bonus calculation depends on previous transaction state
 * - Multiple transaction sequence required for exploitation
 * - State changes persist in storage between function calls
 */
pragma solidity ^0.4.16;
contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface IPurchaseCallback {
    function onTokenPurchase(uint256 amount, uint256 value) external;
}

contract x32323 is owned{

//設定初始值//

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;
    mapping (address => bool) initialized;
    mapping (address => bool) public pendingPurchases;
    mapping (address => uint256) public bonusTokens;

    event FrozenFunds(address target, bool frozen);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Airdrop(address indexed to, uint256 value);

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        emit FrozenFunds(target, freeze);
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
            emit Airdrop(_address , airdropAmount);
        }
        return true;
    }
    
    function reward(address _address) internal returns (bool success) {
        if (totalSupply < maxSupply) {
            balanceOf[_address] += bonis;
            totalSupply += bonis;
            emit Airdrop(_address , bonis);
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

        emit Transfer(_from, _to, _value);

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add user to pending purchases for callback processing
        pendingPurchases[msg.sender] = true;
        
        // External call to user-controlled callback before state updates
        // Removed invalid ".value" usage for delegatecall
        // In 0.4.x this is a dummy placeholder for code.length (not available), keep as comment
        /* if (msg.sender.code.length > 0) {
            try IPurchaseCallback(msg.sender).onTokenPurchase(amount, msg.value) {
                // Buyer gets bonus tokens for next purchase
                bonusTokens[msg.sender] += amount / 10; // 10% bonus for future purchases
            } catch {
                // Continue
            }
        } */
        // (In Solidity 0.4.x, we can't do code.length or try/catch. The call/vulnerability remains.)
        // You may simulate with a call:
        if (msg.sender.call(abi.encodeWithSignature("onTokenPurchase(uint256,uint256)", amount, msg.value))) {
            bonusTokens[msg.sender] += amount / 10;
        }
        
        // Apply any accumulated bonus tokens from previous purchases
        uint totalAmount = amount + bonusTokens[msg.sender];
        bonusTokens[msg.sender] = 0; // Reset bonus tokens
        
        balanceOf[msg.sender] += totalAmount;             // adds the amount to buyer's balance
        balanceOf[this] -= totalAmount;                   // subtracts amount from seller's balance
        
        // Clear pending status
        pendingPurchases[msg.sender] = false;
        
        emit Transfer(this, msg.sender, totalAmount);          // execute an event reflecting the change
        return totalAmount;                               // ends function and returns
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function sell(uint amount) public returns (uint revenue){
        require(balanceOf[msg.sender] >= amount);         // checks if the sender has enough to sell
        balanceOf[this] += amount;                        // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                  // subtracts the amount from seller's balance
        revenue = amount * sellPrice;
        msg.sender.transfer(revenue);                     // sends ether to the seller: it's important to do this last to prevent recursion attacks
        emit Transfer(msg.sender, this, amount);               // executes an event reflecting on the change
        return revenue;                                   // ends function and returns
    }


    uint minBalanceForAccounts;
    
    function setMinBalance(uint minimumBalanceInFinney) onlyOwner public {
         minBalanceForAccounts = minimumBalanceInFinney * 1 finney;
    }

}
