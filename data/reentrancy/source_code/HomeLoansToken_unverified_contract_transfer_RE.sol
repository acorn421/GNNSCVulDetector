/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before state updates
 * 2. Added contract detection with `_to.code.length > 0` to make it realistic
 * 3. Positioned the external call after balance checks but before state modifications
 * 4. Added comment suggesting this is for "compliance hooks" to make it appear legitimate
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Victim calls `transfer()` to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` is called BEFORE the victim's balance is updated
 * 4. **Reentrancy**: The malicious contract calls `transfer()` again while the original call is still executing
 * 5. **State Exploitation**: The second call passes the balance check because the victim's balance hasn't been decremented yet
 * 6. **Multiple Rounds**: The attacker can drain funds progressively across multiple reentrant calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The actual exploitation happens when someone transfers to that contract (Transaction 2+)
 * - The stateful nature means the attacker's contract must be in place before the vulnerable transfer occurs
 * - Each successful reentrancy call creates persistent state changes that enable further exploitation
 * - The attack spans multiple call frames within the same transaction, but requires the pre-positioned malicious contract from a previous transaction
 * 
 * **Stateful Persistence:**
 * - The malicious contract persists between transactions with its exploit code
 * - Balance state changes accumulate across multiple reentrant calls
 * - The vulnerability depends on the persistent state of balances that were established in previous transactions
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

    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract HomeLoansToken is owned {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;
  
    /// @dev Fix for the ERC20 short address attack http://vessenes.com/the-erc20-short-address-attack-explained/
    /// @param size payload size
    modifier onlyPayloadSize(uint size) {
        require(msg.data.length >= size + 4);
        _;
    }

    /* This creates an array with all balances */
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowed;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint value);

    function HomeLoansToken(
        uint256 initialSupply,
        string tokenName,
        uint decimalUnits,
        string tokenSymbol
    ) public {
        owner = msg.sender;
        totalSupply = initialSupply.mul(10 ** decimalUnits);
        balanceOf[msg.sender] = totalSupply; // Give the creator half initial tokens
        name = tokenName; // Set the name for display purposes
        symbol = tokenSymbol; // Set the symbol for display purposes
        decimals = decimalUnits; // Amount of decimals for display purposes
    }

    /// @dev Tranfer tokens to address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transfer(address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns(bool success) {
        require(_to != address(0));
        require(_value <= balanceOf[msg.sender]);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before state update for compliance hooks
        if (extcodesize(_to) > 0) {
            // Call recipient notification - this enables reentrancy
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue even if call fails to maintain backwards compatibility
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // SafeMath.sub will throw if there is not enough balance.
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    /// @dev Tranfer tokens from one address to other
    /// @param _from source address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transferFrom(address _from, address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns(bool success) {
        require(_to != address(0));
        require(_value <= balanceOf[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    /// @dev Destroy Tokens
    ///@param destroyAmount Count Token
    function destroyToken(uint256 destroyAmount) public onlyOwner {
        destroyAmount = destroyAmount.mul(10 ** decimals);
        balanceOf[owner] = balanceOf[owner].sub(destroyAmount);
        totalSupply = totalSupply.sub(destroyAmount);
    }

    /// @dev Approve transfer
    /// @param _spender holder address
    /// @param _value tokens amount
    /// @return result
    function approve(address _spender, uint _value) public returns(bool success) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));

        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /// @dev Token allowance
    /// @param _owner holder address
    /// @param _spender spender address
    /// @return remain amount
    function allowance(address _owner, address _spender) public constant returns(uint remaining) {
        return allowed[_owner][_spender];
    }

    /// @dev Withdraw all owner
    function withdraw() public onlyOwner {
        msg.sender.transfer(this.balance);
    }
    
    // Moved extcodesize helper here for correct Solidity 0.4.x structuring
    function extcodesize(address _addr) internal constant returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }
}
