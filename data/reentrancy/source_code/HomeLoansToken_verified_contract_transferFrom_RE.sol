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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to` address using `onTokenReceived(address,address,uint256)` callback
 * 2. Moved the allowance update (`allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value)`) to occur AFTER the external call
 * 3. Added contract existence check (`_to.code.length > 0`) to make the callback realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker gets approval for large allowance from victim
 * 2. **Transaction 2 (Initial Transfer)**: Attacker calls transferFrom with malicious contract as `_to`
 * 3. **Reentrancy Attack**: During the external call, malicious contract re-enters transferFrom
 * 4. **State Exploitation**: Since allowance hasn't been updated yet, attacker can transfer tokens again with same allowance
 * 5. **Transaction 3+ (Repeated Exploitation)**: Attacker can repeat this process across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires initial allowance setup in a previous transaction
 * - Each exploitation can be chained across multiple transferFrom calls
 * - The persistent state (allowance mapping) allows repeated exploitation until allowance is finally updated
 * - Attacker needs separate transactions to set up victim accounts and execute the attack sequence
 * 
 * **Stateful Nature:**
 * - The `allowed` mapping persists between transactions
 * - Balance states accumulate across multiple exploitations
 * - The vulnerability depends on the sequence of state modifications across transaction boundaries
 * 
 * This creates a realistic vulnerability where the attacker can drain more tokens than they should be allowed to by exploiting the window between balance updates and allowance updates across multiple transaction calls.
 */
pragma solidity ^0.4.21;

contract owned {
    address public owner;

    constructor() public {
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



    constructor(
        uint256 initialSupply,
        string tokenName,
        uint decimalUnits,
        string tokenSymbol
    ) public {
        owner = msg.sender;
        totalSupply = initialSupply.mul(10 ** decimalUnits);
        balanceOf[msg.sender] = totalSupply; // Give the creator all initial tokens
        name = tokenName; // Set the name for display purposes
        symbol = tokenSymbol; // Set the symbol for display purposes
        decimals = decimalUnits; // Amount of decimals for display purposes
    }


    /// @dev Transfer tokens to address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transfer(address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns(bool) {
        require(_to != address(0));
        require(_value <= balanceOf[msg.sender]);

        // SafeMath.sub will throw if there is not enough balance.
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }


    /// @dev Transfer tokens from one address to other
    /// @param _from source address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transferFrom(address _from, address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns(bool) {
        require(_to != address(0));
        require(_value <= balanceOf[_from]);
        require(_value <= allowed[_from][msg.sender]);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before updating allowance (vulnerability injection)
        if (isContract(_to)) {
            // bool extSuccess = false; // removed for ^0.4.x for assignment result
            bytes4 sel = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            // solhint-disable-next-line avoid-low-level-calls
            require(_to.call(abi.encodeWithSelector(sel, _from, msg.sender, _value)), "Token transfer notification failed");
        }
        // Update allowance after external call (state modification after external interaction)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to detect contract (for _to)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
    function approve(address _spender, uint _value) public returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));

        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /// @dev Token allowance
    /// @param _owner holder address
    /// @param _spender spender address
    /// @return remain amount
    function allowance(address _owner, address _spender) public view returns(uint) {
        return allowed[_owner][_spender];
    }

    /// @dev Withdraw all owner
    function withdraw() public onlyOwner {
        owner.transfer(address(this).balance);
    }
}
