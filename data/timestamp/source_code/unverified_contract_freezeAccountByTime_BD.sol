/*
 * ===== SmartInject Injection Details =====
 * Function      : freezeAccountByTime
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
 * This vulnerability introduces timestamp dependence through dynamic calculations that create exploitable variations in freeze duration and token release rates across multiple transactions. The exploit requires:
 * 
 * 1. **Transaction 1**: Owner calls freezeAccountByTime() at a strategically chosen timestamp where (now % 10) and (now % 100) produce favorable values for shorter freeze duration and higher release rates.
 * 
 * 2. **Transaction 2+**: The stored timestamp-dependent values (time_end_frozen, realsestep) are used by other functions like _refulshFrozenInfo(), QueryFrozenCoins(), and _transfer() in subsequent transactions. Since these values were calculated based on the timestamp from Transaction 1, they create predictable vulnerabilities.
 * 
 * The vulnerability is multi-transaction because:
 * - The timestamp-dependent calculations in freezeAccountByTime() create persistent state
 * - This state is consumed by other functions in later transactions
 * - Miners can manipulate block timestamps to influence both the initial calculation and subsequent usage
 * - The exploit requires timing the initial call and then leveraging the stored vulnerable state in follow-up transactions
 * 
 * This creates a stateful vulnerability where the timing of the first transaction determines the exploitability in future transactions.
 */
pragma solidity ^0.4.21;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}


contract TokenERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;

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
        emit Transfer(_from, _to, _value);
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

}

/******************************************/
/*       ADVANCED TOKEN STARTS HERE       */
/******************************************/

contract BBBSToken is owned, TokenERC20 {
    struct frozenInfo {
       bool frozenAccount;
       bool frozenAccBytime;
       // uint time_stfrozen;
       uint time_end_frozen;
       uint time_last_query;
       uint256 frozen_total;
       // uint256 realsestep;
    }
    
    struct frozenInfo_prv {
       uint256 realsestep;
    }
    
    uint private constant timerate = 1;
    string public declaration = "frozenInfos will reflush by function QueryFrozenCoins and transfer.";
    // mapping (address => bool) public frozenAccount;
    mapping (address => frozenInfo) public frozenInfos;
    mapping (address => frozenInfo_prv) private frozenInfos_prv;
    
    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);

    // This notifies clients about the frozen coin
    event FrozenTotal(address indexed from, uint256 value);
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BBBSToken(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}
    
    function _resetFrozenInfo(address target) internal {
       frozenInfos[target].frozen_total = 0;
       frozenInfos[target].time_end_frozen = 0;
       frozenInfos_prv[target].realsestep = 0;
       frozenInfos[target].time_last_query = 0;
       frozenInfos[target].frozenAccBytime = false; 
    }
    
    function _refulshFrozenInfo(address target) internal {
       if(frozenInfos[target].frozenAccBytime) 
        {
            uint nowtime = now ;// + 60*60*24*365*5 ;
            frozenInfos[target].time_last_query = nowtime;
            if(nowtime>=frozenInfos[target].time_end_frozen)
            {
               _resetFrozenInfo(target);              
            }
            else
            {
               uint stepcnt = frozenInfos[target].time_end_frozen - nowtime;
               uint256 releasecoin = stepcnt * frozenInfos_prv[target].realsestep;
               if(frozenInfos[target].frozen_total<=releasecoin)
                  _resetFrozenInfo(target);
               else
               {
                  frozenInfos[target].frozen_total=releasecoin;
               }
            }
        }       
    }
    
    /* Internal transfer, only can be called by this contract */
    
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        // require(!frozenAccount[_from]);                     // Check if sender is frozen
        // require(!frozenAccount[_to]);                       // Check if recipient is frozen
        require(!frozenInfos[_from].frozenAccount);                     // Check if sender is frozen
        require(!frozenInfos[_to].frozenAccount);                       // Check if recipient is frozen
        require(!frozenInfos[_to].frozenAccBytime); 
                
        if(frozenInfos[_from].frozenAccBytime) 
        {
            _refulshFrozenInfo(_from);
            if(frozenInfos[_from].frozenAccBytime)
            {
               if((balanceOf[_from]-_value)<=frozenInfos[_from].frozen_total)
                   require(false);
            }
        }
        
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
    }

    /// @notice `freeze? Prevent | Allow` `target` from sending & receiving tokens
    /// @param target Address to be frozen
    /// @param freeze either to freeze it or not
    function freezeAccount(address target, bool freeze) onlyOwner public {
        // frozenAccount[target] = freeze;
        frozenInfos[target].frozenAccount = freeze;
        emit FrozenFunds(target, freeze);
    }
    
    function freezeAccountByTime(address target, uint time) onlyOwner public {
        // frozenAccount[target] = freeze;
        require (target != 0x0);
        require (balanceOf[target] >= 1); 
        require(!frozenInfos[target].frozenAccBytime);
        require (time >0);
        frozenInfos[target].frozenAccBytime = true;
        uint nowtime = now;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable: Use block.timestamp modulo for dynamic timerate calculation
        // This creates timestamp dependence that can be exploited across multiple transactions
        uint dynamicTimerate = (nowtime % 10) + 1; // Range: 1-10 based on timestamp
        
        // Store the timestamp-dependent values that will be used in future transactions
        frozenInfos[target].time_end_frozen = nowtime + time * dynamicTimerate;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        frozenInfos[target].time_last_query = nowtime;
        frozenInfos[target].frozen_total = balanceOf[target];
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable: Base release step on timestamp-dependent calculation
        // This affects how coins are released in subsequent transactions
        uint timestampFactor = (nowtime % 100) + 1; // Range: 1-100
        frozenInfos_prv[target].realsestep = (frozenInfos[target].frozen_total * timestampFactor) / (time * dynamicTimerate * 100);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require (frozenInfos_prv[target].realsestep>0);      
        emit FrozenTotal(target, frozenInfos[target].frozen_total);
    }    
    
    function UnfreezeAccountByTime(address target) onlyOwner public {
        _resetFrozenInfo(target);
        emit FrozenTotal(target, frozenInfos[target].frozen_total);
    }
    
    function QueryFrozenCoins(address _from) public returns (uint256 total) {
        require (_from != 0x0);
        require(frozenInfos[_from].frozenAccBytime);
        _refulshFrozenInfo(_from);        
        emit FrozenTotal(_from, frozenInfos[_from].frozen_total);
        return frozenInfos[_from].frozen_total;
    }

}