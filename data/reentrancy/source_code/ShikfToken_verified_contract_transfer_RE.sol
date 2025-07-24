/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability exploits the startBalance distribution mechanism through multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(bytes4(keccak256("tokensReceived(address,uint256)")), msg.sender, _value)` before balance updates
 * 2. The call occurs after balance checks but before state modifications, violating the CEI pattern
 * 3. The call allows the recipient to re-enter the transfer function while balances are still in their pre-update state
 * 
 * **Multi-Transaction Exploitation:**
 * Transaction 1: Attacker calls transfer() to a malicious contract address. The malicious contract receives the tokensReceived callback and can:
 * - Re-enter transfer() while the original sender's balance hasn't been decremented yet
 * - Exploit the startBalance distribution by triggering it multiple times across different addresses
 * - Build up accumulated state that enables further exploitation
 * 
 * Transaction 2: The attacker can then use the accumulated state from Transaction 1 to drain tokens by:
 * - Leveraging the fact that touched[msg.sender] state persists between transactions
 * - Exploiting the timing window where balances are checked but not yet updated
 * - Using the currentTotalSupply accumulation to bypass distribution limits
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent state of the 'touched' mapping and 'currentTotalSupply' accumulation
 * - The startBalance distribution can only be triggered once per address, requiring multiple addresses/transactions
 * - The exploit builds up state across transactions where each reentrancy call can manipulate the distribution mechanism
 * - Single transaction exploitation is limited by gas limits and the one-time nature of the startBalance distribution
 */
pragma solidity ^0.4.18;


library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }
}


contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function Ownable() public {
        owner = msg.sender;
    }

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function transferOwnership(address newOwner) public onlyOwner {
            require(newOwner != address(0));
            OwnershipTransferred(owner, newOwner);
            owner = newOwner;
        }

}


contract ShikfToken is Ownable{

    using SafeMath for uint256;

                       string public constant name       = "shikefa";
    string public constant symbol     = "SKF";
    uint32 public constant decimals   = 18;
    uint256 public totalSupply        = 21000000 ether;
    uint256 public currentTotalSupply = 0;
    uint256 startBalance              = 100 ether;

    mapping(address => bool) touched;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);


    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        if( !touched[msg.sender] && currentTotalSupply < totalSupply ){
            balances[msg.sender] = balances[msg.sender].add( startBalance );
            touched[msg.sender] = true;
            currentTotalSupply = currentTotalSupply.add( startBalance );
        }

        require(_value <= balances[msg.sender]);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient before state updates - creates reentrancy opportunity
        if(_to.call(bytes4(keccak256("tokensReceived(address,uint256)")), msg.sender, _value)) {
            // Call succeeded - continue with transfer
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);

        Transfer(msg.sender, _to, _value);
        return true;
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        require(_value <= allowed[_from][msg.sender]);

        if( !touched[_from] && currentTotalSupply < totalSupply ){
            touched[_from] = true;
            balances[_from] = balances[_from].add( startBalance );
            currentTotalSupply = currentTotalSupply.add( startBalance );
        }

        require(_value <= balances[_from]);

        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }


    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }


    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
    }


    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
        Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }


    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
        }
        Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }


    function getBalance(address _a) internal constant returns(uint256)
    {
        if( currentTotalSupply < totalSupply ){
            if( touched[_a] )
                return balances[_a];
            else
                return balances[_a].add( startBalance );
        } else {
            return balances[_a];
        }
    }


    function balanceOf(address _owner) public view returns (uint256 balance) {
        return getBalance( _owner );
    }
}