/*
 * ===== SmartInject Injection Details =====
 * Function      : multisend
 * Vulnerability : Timestamp Dependence
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
 * Introduced a timestamp-dependent daily transfer limit system that relies on block.timestamp for time calculations. The vulnerability is exploitable through timestamp manipulation across multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added state variables: `lastMultisendTime` mapping to track last multisend timestamp per user, `dailyTransferTotal` mapping to track accumulated transfers, and `dailyTransferLimit` constant
 * 2. Implemented time-based logic that resets daily counters when `block.timestamp >= lastMultisendTime[msg.sender] + 86400`
 * 3. Added daily transfer limit validation using accumulated state from previous transactions
 * 4. Updated state variables at the end of each function call to persist across transactions
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls multisend() with maximum allowed amount (1M tokens), setting their `lastMultisendTime` to current block.timestamp
 * 2. **Transaction 2**: Attacker (if they're a miner) or through miner collaboration manipulates the next block's timestamp to be >= lastMultisendTime + 86400, effectively "fast-forwarding" time
 * 3. **Transaction 3**: Attacker calls multisend() again, and the manipulated timestamp causes the daily counter to reset, allowing another 1M token transfer
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation across transactions (dailyTransferTotal must build up)
 * - The timestamp comparison relies on the state from previous transactions (lastMultisendTime)
 * - A single transaction cannot exploit this as it requires the state to be set in one transaction and then manipulated in subsequent transactions
 * - The exploit depends on the sequence: establish state → manipulate time → bypass restriction
 * 
 * **Realistic Exploitation Scenarios:**
 * - Miners can manipulate block.timestamp within reasonable bounds (±15 seconds typically)
 * - Attackers could coordinate multiple transactions around actual day boundaries
 * - In private/consortium blockchains, timestamp manipulation is more feasible
 * - The 86400 second calculation assumes perfect day boundaries, but block.timestamp is miner-controlled
 */
pragma solidity ^0.4.19;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}

contract ERC20 {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function ERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
        name = tokenName;                                       // Set the name for display purposes
        symbol = tokenSymbol;                                   // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);

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
/*       FMC TOKEN STARTS HERE       */
/******************************************/

contract FreeManCoin is ERC20 {


    /* Initializes contract with initial supply tokens to the creator of the contract */
    function FreeManCoin() ERC20(50000000, "FreeMan Coin", "FMC") public {}


    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastMultisendTime;
    mapping(address => uint256) public dailyTransferTotal;
    uint256 public dailyTransferLimit = 1000000; // 1M token limit per day
    
    function multisend(address[] dests, uint256[] values) public returns (uint256) {
        // Reset daily counter if a new day has started (based on block timestamp)
        if (block.timestamp >= lastMultisendTime[msg.sender] + 86400) {
            dailyTransferTotal[msg.sender] = 0;
        }
        
        // Calculate total transfer amount for this multisend
        uint256 totalTransfer = 0;
        for (uint256 j = 0; j < values.length; j++) {
            totalTransfer += values[j];
        }
        
        // Check daily transfer limit
        require(dailyTransferTotal[msg.sender] + totalTransfer <= dailyTransferLimit, "Daily transfer limit exceeded");
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 i = 0;
        while (i < dests.length) {
           transfer(dests[i], values[i]);
           i += 1;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update state variables with current timestamp and accumulated transfers
        lastMultisendTime[msg.sender] = block.timestamp;
        dailyTransferTotal[msg.sender] += totalTransfer;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return(i);
    }
    
}