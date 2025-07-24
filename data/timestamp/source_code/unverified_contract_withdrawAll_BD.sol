/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawAll
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced timestamp dependence vulnerability by adding time-based withdrawal restrictions using block.timestamp. The vulnerability creates a stateful, multi-transaction exploit where:
 * 
 * 1. **State Variables Added** (assumed to exist in contract):
 *    - `lastWithdrawalTime`: Tracks when last withdrawal occurred
 *    - `contractDeployTime`: Records contract deployment time
 *    - `totalWithdrawn`: Accumulates total withdrawn amount
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner attempts withdrawal but may be blocked by 24-hour cooldown
 *    - **Transaction 2**: After cooldown period, withdrawal succeeds but amount is limited by time-based calculation
 *    - **Transaction 3**: Miner manipulation or timing attacks can bypass restrictions
 * 
 * 3. **Specific Vulnerabilities**:
 *    - **Miner Manipulation**: Miners can manipulate `block.timestamp` by up to 900 seconds to bypass cooldown periods
 *    - **Time-Based Calculation Flaw**: Using `block.timestamp` for withdrawal limits creates predictable patterns
 *    - **State Persistence**: The `lastWithdrawalTime` state persists between transactions, enabling timing-based attacks
 * 
 * 4. **Exploitation Scenarios**:
 *    - **Scenario A**: Miner sets `block.timestamp` backwards in Transaction 1 to reset cooldown, then forwards in Transaction 2 to maximize withdrawal amount
 *    - **Scenario B**: Attacker waits for natural timestamp progression but exploits the predictable time-based calculation to drain funds systematically
 *    - **Scenario C**: Multiple transactions over time manipulate the accumulated state to bypass intended security restrictions
 * 
 * The vulnerability maintains the original function's purpose while introducing realistic timing-based security measures that can be exploited through timestamp manipulation across multiple transactions.
 */
pragma solidity ^0.4.24;

contract ERC20 {
  uint256 public totalSupply;

  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  function allowance(address owner, address spender) public view returns (uint256);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);

  event Approval(address indexed owner, address indexed spender, uint256 value);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

contract SPYdeployer {

    address public owner;
    string public  name;
    event OwnershipTransferred(address indexed _from, address indexed _to);
    
    uint256 public lastWithdrawalTime;
    uint256 public contractDeployTime;
    uint256 public totalWithdrawn;
    
    constructor() public {
        owner = address(0x6968a3cDc11f71a85CDd13BB2792899E5D215DbB); // The reserves wallet address
        contractDeployTime = block.timestamp;
        lastWithdrawalTime = 0;
        totalWithdrawn = 0;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    // transfer Ownership to other address
    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0x0));
        emit OwnershipTransferred(owner,_newOwner);
        owner = _newOwner;
    }
    

    // keep all tokens sent to this address
    function() payable public {
        emit Received(msg.sender, msg.value);
    }

    // callable by owner only, after specified time
    function withdrawAll() onlyOwner public {
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
       // Security enhancement: prevent frequent withdrawals
       require(block.timestamp >= lastWithdrawalTime + 24 hours, "Withdrawal too frequent");
       
       // Calculate withdrawal amount based on time elapsed
       uint256 timeElapsed = block.timestamp - contractDeployTime;
       uint256 maxWithdrawal = (timeElapsed / 1 days) * 1 ether;
       
       uint256 withdrawAmount = address(this).balance;
       if (withdrawAmount > maxWithdrawal) {
           withdrawAmount = maxWithdrawal;
       }
       
       // Update state for next withdrawal
       lastWithdrawalTime = block.timestamp;
       totalWithdrawn += withdrawAmount;
       
       // withdraw balance
       msg.sender.transfer(withdrawAmount);
       emit Withdrew(msg.sender, withdrawAmount);
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20(address _tokenContract) onlyOwner public {
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       token.transfer(owner, tokenBalance);
       emit WithdrewTokens(_tokenContract, msg.sender, tokenBalance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20Amount(address _tokenContract, uint256 _amount) onlyOwner public {
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       require(tokenBalance >= _amount, "Not enough funds in the reserve");
       token.transfer(owner, _amount);
       emit WithdrewTokens(_tokenContract, msg.sender, _amount);
    }


    event Received(address from, uint256 amount);
    event Withdrew(address to, uint256 amount);
    event WithdrewTokens(address tokenContract, address to, uint256 amount);
}
