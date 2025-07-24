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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a withdrawal queue system with cooldown periods. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: The function uses `pendingWithdrawals` mapping to track accumulated withdrawal amounts across multiple transactions.
 * 
 * 2. **Time-Based State**: The `lastWithdrawalTime` mapping creates persistent state that affects future function calls.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: User calls sell() to accumulate pending withdrawals
 *    - Transaction 2: After cooldown period, user calls sell() again to trigger withdrawal processing
 *    - During the external call in the withdrawal processing, the attacker can reenter and manipulate the pending withdrawal state
 * 
 * 4. **Reentrancy Window**: The vulnerability exists because the external call `msg.sender.transfer(withdrawAmount)` happens before the pending withdrawal state is properly cleared, and the accumulated state persists between transactions.
 * 
 * 5. **Realistic Implementation**: The withdrawal queue with cooldown is a common pattern in DeFi protocols for rate limiting, making this vulnerability realistic and subtle.
 * 
 * The attacker needs to:
 * - First transaction: Call sell() to set up pending withdrawals
 * - Wait for cooldown period
 * - Second transaction: Call sell() again to trigger withdrawal processing
 * - During the transfer call, reenter to manipulate the persistent state variables
 * 
 * This creates a stateful reentrancy where the vulnerability can only be exploited through coordinated multi-transaction attacks that leverage the accumulated state across different transactions.
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

contract TokenERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TokenERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
}

/******************************************/
/*       OLIGARCH TOKEN STARTS HERE       */
/******************************************/

contract Oligarch is owned, TokenERC20 {

    uint256 public sellPrice;
    uint256 public buyPrice;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function Oligarch(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] > _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Allow users to buy tokens for `newBuyPrice` eth and sell tokens for `newSellPrice` eth
    /// @param newSellPrice Price the users can sell to the contract
    /// @param newBuyPrice Price users can buy from the contract
    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner public {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    /// @notice Buy tokens from contract by sending ether
    function buy() payable public {
        uint amount = msg.value / buyPrice;               // calculates the amount
        _transfer(this, msg.sender, amount);              // makes the transfers
    }

    /// @notice Sell `amount` tokens to contract
    /// @param amount amount of tokens to be sold
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public lastWithdrawalTime;
    uint256 public withdrawalCooldown = 1 hours;
    
    function sell(uint256 amount) public {
        require(this.balance >= amount * sellPrice);      // checks if the contract has enough ether to buy
        
        // Check if user has pending withdrawal and cooldown has passed
        if (pendingWithdrawals[msg.sender] > 0 && block.timestamp >= lastWithdrawalTime[msg.sender] + withdrawalCooldown) {
            uint256 withdrawAmount = pendingWithdrawals[msg.sender];
            pendingWithdrawals[msg.sender] = 0;
            lastWithdrawalTime[msg.sender] = block.timestamp;
            
            // Vulnerable: External call before clearing pending withdrawal creates reentrancy window
            msg.sender.transfer(withdrawAmount);
        }
        
        _transfer(msg.sender, this, amount);              // makes the transfers
        
        // Add current sale to pending withdrawals (stateful across transactions)
        pendingWithdrawals[msg.sender] += amount * sellPrice;
        
        // If no previous withdrawal or cooldown passed, allow immediate withdrawal
        if (lastWithdrawalTime[msg.sender] == 0 || block.timestamp >= lastWithdrawalTime[msg.sender] + withdrawalCooldown) {
            uint256 immediateWithdraw = pendingWithdrawals[msg.sender];
            pendingWithdrawals[msg.sender] = 0;
            lastWithdrawalTime[msg.sender] = block.timestamp;
            msg.sender.transfer(immediateWithdraw);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}