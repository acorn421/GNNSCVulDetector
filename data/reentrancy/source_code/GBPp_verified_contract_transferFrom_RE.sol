/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before updating allowances. The vulnerability exploits the window between balance updates and allowance updates, allowing malicious contracts to re-enter and manipulate the transfer process across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract via `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))`
 * 2. Positioned the external call after balance updates but before allowance updates
 * 3. Added contract detection using `_to.code.length > 0` to make the call conditional on the recipient being a contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker sets up allowance via `approve()` and deploys malicious recipient contract
 * 2. **Transaction 2**: Victim calls `transferFrom()` with attacker's contract as `_to`
 * 3. **During Transaction 2**: Malicious contract's `onTokenReceived` hook is called, allowing re-entry
 * 4. **Re-entry**: Attacker calls `transferFrom()` again before allowance is decremented, potentially draining more tokens than authorized
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires prior allowance setup (Transaction 1) and then the exploitation during transfer (Transaction 2)
 * - The attack relies on the persistent state of allowances between transactions
 * - Re-entry during the transfer creates a window where allowance hasn't been updated yet, enabling multiple transfers with the same allowance
 * - The exploit accumulates damage across the re-entrant calls within the second transaction, leveraging state that persists from the first transaction
 * 
 * **Realistic Integration:**
 * This pattern mimics real-world ERC-20 extensions that notify recipient contracts about incoming transfers, making it a subtle and realistic vulnerability that could easily be overlooked in code reviews.
 */
pragma solidity ^0.4.17;

/// @title CurrencyToken contract
contract GBPp {

    address public server; // Address, which the platform website uses.
    address public populous; // Address of the Populous bank contract.

    uint256 public totalSupply;
    bytes32 public name;// token name, e.g, pounds for fiat UK pounds.
    uint8 public decimals;// How many decimals to show. ie. There could 1000 base units with 3 decimals. Meaning 0.980 SBX = 980 base units. It's like comparing 1 wei to 1 ether.
    bytes32 public symbol;// An identifier: eg SBX.

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    //EVENTS
    // An event triggered when a transfer of tokens is made from a _from address to a _to address.
    event Transfer(
        address indexed _from, 
        address indexed _to, 
        uint256 _value
    );
    // An event triggered when an owner of tokens successfully approves another address to spend a specified amount of tokens.
    event Approval(
        address indexed _owner, 
        address indexed _spender, 
        uint256 _value
    );
    // event EventMintTokens(bytes32 currency, uint amount);

    // MODIFIERS

    modifier onlyServer {
        require(isServer(msg.sender) == true);
        _;
    }

    modifier onlyServerOrOnlyPopulous {
        require(isServer(msg.sender) == true || isPopulous(msg.sender) == true);
        _;
    }

    modifier onlyPopulous {
        require(isPopulous(msg.sender) == true);
        _;
    }
    // NON-CONSTANT METHODS
    
    /** @dev Creates a new currency/token.
      * param _decimalUnits The decimal units/places the token can have.
      * param _tokenSymbol The token's symbol, e.g., GBP.
      * param _decimalUnits The tokens decimal unites/precision
      * param _amount The amount of tokens to create upon deployment
      * param _owner The owner of the tokens created upon deployment
      * param _server The server/admin address
      */
    constructor()
        public
    {
        populous = server = 0x63d509F7152769Ddf162eD048B83719fE1e31080;
        symbol = name = 0x47425070; // Set the name for display purposes
        decimals = 6; // Amount of decimals for display purposes
        balances[server] = safeAdd(balances[server], 10000000000000000);
        totalSupply = safeAdd(totalSupply, 10000000000000000);
    }

    // ERC20

    //Note.. Need to emit event, Pokens destroyed... from system
    /** @dev Destroys a specified amount of tokens 
      * @dev The method uses a modifier from withAccessManager contract to only permit populous to use it.
      * @dev The method uses SafeMath to carry out safe token deductions/subtraction.
      * @param amount The amount of tokens to create.
      */

    function destroyTokens(uint amount) public onlyPopulous returns (bool success) {
        if (balances[populous] < amount) {
            return false;
        } else {
            balances[populous] = safeSub(balances[populous], amount);
            totalSupply = safeSub(totalSupply, amount);
            return true;
        }
    }

    
    /** @dev Destroys a specified amount of tokens, from a user.
      * @dev The method uses a modifier from withAccessManager contract to only permit populous to use it.
      * @dev The method uses SafeMath to carry out safe token deductions/subtraction.
      * @param amount The amount of tokens to create.
      */
    function destroyTokensFrom(uint amount, address from) public onlyPopulous returns (bool success) {
        if (balances[from] < amount) {
            return false;
        } else {
            balances[from] = safeSub(balances[from], amount);
            totalSupply = safeSub(totalSupply, amount);
            return true;
        }
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient for transfer notification (before allowance update)
        // Note: Removed _to.code.length > 0, not available in Solidity 0.4.x
        if (isContract(_to)) {
            // Call onTokenReceived hook if recipient is a contract
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        }
        
        // Update allowance after external call (vulnerable to reentrancy)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if address is contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }


    // ACCESS MANAGER

    /** @dev Checks a given address to determine whether it is populous address.
      * @param sender The address to be checked.
      * @return bool returns true or false is the address corresponds to populous or not.
      */
    function isPopulous(address sender) public view returns (bool) {
        return sender == populous;
    }

        /** @dev Changes the populous contract address.
      * @dev The method requires the message sender to be the set server.
      * @param _populous The address to be set as populous.
      */
    function changePopulous(address _populous) public {
        require(isServer(msg.sender) == true);
        populous = _populous;
    }

    // CONSTANT METHODS
    
    /** @dev Checks a given address to determine whether it is the server.
      * @param sender The address to be checked.
      * @return bool returns true or false is the address corresponds to the server or not.
      */
    function isServer(address sender) public view returns (bool) {
        return sender == server;
    }

    /** @dev Changes the server address that is set by the constructor.
      * @dev The method requires the message sender to be the set server.
      * @param _server The new address to be set as the server.
      */
    function changeServer(address _server) public {
        require(isServer(msg.sender) == true);
        server = _server;
    }


    // SAFE MATH


      /** @dev Safely multiplies two unsigned/non-negative integers.
    * @dev Ensures that one of both numbers can be derived from dividing the product by the other.
    * @param a The first number.
    * @param b The second number.
    * @return uint The expected result.
    */
    function safeMul(uint a, uint b) internal pure returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

  /** @dev Safely subtracts one number from another
    * @dev Ensures that the number to subtract is lower.
    * @param a The first number.
    * @param b The second number.
    * @return uint The expected result.
    */
    function safeSub(uint a, uint b) internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

  /** @dev Safely adds two unsigned/non-negative integers.
    * @dev Ensures that the sum of both numbers is greater or equal to one of both.
    * @param a The first number.
    * @param b The second number.
    * @return uint The expected result.
    */
    function safeAdd(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        assert(c>=a && c>=b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }
}