/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawERC20
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability that requires multiple function calls to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added state variables: `withdrawalCounts` mapping to track withdrawal attempts per token, `withdrawalInProgress` for reentrancy protection, and `WITHDRAWAL_LIMIT` constant
 * 2. Implemented conditional reentrancy protection that weakens after multiple legitimate transactions
 * 3. After the withdrawal limit is exceeded, the function removes proper reentrancy protection under the guise of "trusted token optimization"
 * 4. State updates occur AFTER external calls when the limit is exceeded, creating the classic reentrancy vulnerability pattern
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Phase 1 (Transactions 1-3)**: Owner makes 3 legitimate withdrawals for a token, each increments `withdrawalCounts[token]`
 * 2. **Phase 2 (Transaction 4+)**: Once limit exceeded, the function enters vulnerable mode where `withdrawalInProgress` is set to false AFTER the external call
 * 3. **Exploitation**: A malicious token contract can now use its `transfer` function to re-enter `withdrawERC20`, since the reentrancy protection is removed and state is updated after external calls
 * 
 * **Why Multiple Transactions Required:**
 * - The vulnerability is NOT exploitable in early transactions (1-3) due to proper reentrancy protection
 * - State accumulation (`withdrawalCounts`) must reach the threshold through multiple legitimate transactions
 * - Only after the accumulated state exceeds `WITHDRAWAL_LIMIT` does the vulnerability become exploitable
 * - This creates a realistic scenario where legitimate usage over time eventually enables the security flaw
 * 
 * **Realistic Nature:**
 * - The code appears to implement "performance optimization" for frequently used tokens
 * - The withdrawal counting mechanism seems like legitimate access control
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - Mirrors real-world patterns where optimizations introduce security flaws
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
    
    constructor() public {
        
        owner = address(0x6968a3cDc11f71a85CDd13BB2792899E5D215DbB); // The reserves wallet address
        
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
       // withdraw balance
       msg.sender.transfer(address(this).balance);
       emit Withdrew(msg.sender, address(this).balance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public withdrawalCounts;
mapping(address => bool) public withdrawalInProgress;
uint256 public constant WITHDRAWAL_LIMIT = 3;

function withdrawERC20(address _tokenContract) onlyOwner public {
       require(!withdrawalInProgress[_tokenContract], "Withdrawal already in progress");
       
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       
       // Track withdrawal attempts - state accumulation
       withdrawalCounts[_tokenContract]++;
       
       // After multiple withdrawals, disable protection for "performance optimization"
       if (withdrawalCounts[_tokenContract] <= WITHDRAWAL_LIMIT) {
           withdrawalInProgress[_tokenContract] = true;
           token.transfer(owner, tokenBalance);
           withdrawalInProgress[_tokenContract] = false;
       } else {
           // Vulnerability: Remove reentrancy protection after limit exceeded
           // This appears as "trusted token optimization" but enables reentrancy
           token.transfer(owner, tokenBalance);
           // State update happens AFTER external call - classic reentrancy pattern
           withdrawalInProgress[_tokenContract] = false;
       }
       
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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