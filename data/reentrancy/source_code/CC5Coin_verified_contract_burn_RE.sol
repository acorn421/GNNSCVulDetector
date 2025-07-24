/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `burnFeeCollector.call()` before state updates
 * - The external call occurs after balance validation but before balance/supply modifications
 * - Used low-level `call()` to invoke `notifyBurn(address,uint256)` on external contract
 * - The call happens only if `burnFeeCollector` address is set (realistic conditional logic)
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract as `burnFeeCollector`
 * - Contract owner sets the attacker's contract as the burn fee collector
 * - Attacker has balance of 1000 tokens
 * 
 * **Transaction 2 (First Burn Attempt):**
 * - Attacker calls `burn(500)` 
 * - Balance check passes (1000 >= 500)
 * - External call to malicious `burnFeeCollector.notifyBurn()` triggers
 * - Malicious contract re-enters `burn(500)` again
 * - Second call sees original balance (1000) since state not yet updated
 * - Both calls pass validation with same initial balance
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - State from previous transactions persists
 * - Attacker can continue exploiting the reentrancy window
 * - Each new transaction builds on accumulated state changes
 * - Can burn more tokens than actually owned across multiple transactions
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Persistence**: The vulnerability exploits the fact that `balanceOf` and `totalSupply` state persists between transactions
 * - **Accumulated Effect**: Each reentrancy call affects global state that influences subsequent transactions
 * - **Setup Dependency**: Requires initial setup of malicious `burnFeeCollector` contract
 * - **Sequence Dependency**: Each transaction builds on the state changes from previous ones
 * - **Not Single-Transaction**: The exploit requires coordination across multiple calls that each modify persistent contract state
 * 
 * **4. Realistic Integration:**
 * - Burn fee collection is a common pattern in token contracts
 * - External notification systems are frequently used in production
 * - The conditional check makes the vulnerability subtle and realistic
 * - Maintains all original functionality while introducing the security flaw
 * 
 * **5. Exploitation Impact:**
 * - Can burn more tokens than actually owned
 * - Can manipulate `totalSupply` beyond intended limits
 * - State inconsistencies accumulate across transactions
 * - Requires sequence of operations making it a true multi-transaction vulnerability
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract CC5Coin is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    address public burnFeeCollector;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
    
    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);
        string tokenName;
        uint8 decimalUnits;
        string tokenSymbol;
        uint256 public mined_coin_supply = 0;
        uint256 public pre_mined_supply = 0;
        uint256 public circulating_supply = 0;
        uint256 public reward = 5000000000;
        uint256 public timeOfLastHalving = now;
        uint public timeOfLastIncrease = now;
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CC5Coin() {
        //balanceOf[msg.sender] = 2100000000000000;              // Give the creator all initial tokens
        totalSupply = 2100000000000000;                        // Update total supply
        name = "CChips Coin";                            // Set the name for display purposes
        symbol = "CC5";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
        owner = msg.sender;
        timeOfLastHalving = now;
    }

    function updateSupply() internal returns (uint256) {

      if (now - timeOfLastHalving >= 2100000 minutes) {
        reward /= 2;
        timeOfLastHalving = now;
      }

      if (now - timeOfLastIncrease >= 150 seconds) {
        uint256 increaseAmount = ((now - timeOfLastIncrease) / 10 seconds) * reward;
      if (totalSupply>(pre_mined_supply+increaseAmount))
        {
          pre_mined_supply += increaseAmount;
          mined_coin_supply += increaseAmount;
          timeOfLastIncrease = now;
        }
      }

      circulating_supply = pre_mined_supply - mined_coin_supply;

      return circulating_supply;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
        
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;                                           // Check if the sender has enough
        if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to burn fee collector before state updates - creates reentrancy window
        if (burnFeeCollector != 0x0) {
            burnFeeCollector.call(bytes4(keccak256("notifyBurn(address,uint256)")), msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);            // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;                                       // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);        // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;                                       // Check if the sender has enough
        if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);          // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
    
    // transfer balance to owner
    function withdrawEther(uint256 amount) {
        if(msg.sender != owner)throw;
        owner.transfer(amount);
    }


    
    function mint(uint256 _value) {
        if(msg.sender != owner)throw;
        else{
            mined_coin_supply -= _value; // Remove from unspent supply
            balanceOf[msg.sender] =SafeMath.safeAdd(balanceOf[msg.sender], _value);  // Add the same to the recipient
            updateSupply();
        }

    }
    
    // can accept ether
    function() payable {
    }
}
