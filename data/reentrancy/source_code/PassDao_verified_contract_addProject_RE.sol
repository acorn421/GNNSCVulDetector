/*
 * ===== SmartInject Injection Details =====
 * Function      : addProject
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the project address before finalizing the projectID mapping. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys malicious contract and calls addProject with their contract address
 *    - The function increments projects.length and creates project entry
 *    - External call to attacker's contract triggers onProjectRegistered
 *    - During reentrancy, attacker can call addProject again with different address
 *    - Second call sees projectID[attackerAddress] still == 0 (not set yet)
 *    - This creates overlapping project IDs and inconsistent state
 * 
 * 2. **Transaction 2 (Exploitation)**: Attacker calls addProject with legitimate project address
 *    - Due to corrupted state from Transaction 1, legitimate project gets wrong ID
 *    - Attacker can manipulate project assignments and access controls
 *    - State inconsistencies persist between transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires building up inconsistent state across multiple calls
 * - Single transaction reentrancy would be caught by gas limits or stack depth
 * - The attack needs time for state to settle between transactions to be effective
 * - Multiple transactions allow the attacker to create a complex state corruption pattern
 * 
 * **State Persistence Elements:**
 * - projects.length counter gets corrupted across transactions
 * - projectID mapping inconsistencies accumulate
 * - Each transaction builds upon previous state corruption
 * - The attack effectiveness grows with each additional transaction
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to fully exploit, making it a sophisticated attack vector that traditional single-transaction reentrancy guards might miss.
 */
pragma solidity ^0.4.8;

/*
This file is part of Pass DAO.

Pass DAO is free software: you can redistribute it and/or modify
it under the terms of the GNU lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Pass DAO is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU lesser General Public License for more details.

You should have received a copy of the GNU lesser General Public License
along with Pass DAO.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
Smart contract for a Decentralized Autonomous Organization (DAO)
to automate organizational governance and decision-making.
*/

/// @title Pass Dao smart contract
contract PassDao {
    
    struct revision {
        // Address of the Committee Room smart contract
        address committeeRoom;
        // Address of the share manager smart contract
        address shareManager;
        // Address of the token manager smart contract
        address tokenManager;
        // Address of the project creator smart contract
        uint startDate;
    }
    // The revisions of the application until today
    revision[] public revisions;

    struct project {
        // The address of the smart contract
        address contractAddress;
        // The unix effective start date of the contract
        uint startDate;
    }
    // The projects of the Dao
    project[] public projects;

    // Map with the indexes of the projects
    mapping (address => uint) projectID;
    
    // The address of the meta project
    address metaProject;

    
// Events

    event Upgrade(uint indexed RevisionID, address CommitteeRoom, address ShareManager, address TokenManager);
    event NewProject(address Project);

// Constant functions  
    
    /// @return The effective committee room
    function ActualCommitteeRoom() constant returns (address) {
        return revisions[0].committeeRoom;
    }
    
    /// @return The meta project
    function MetaProject() constant returns (address) {
        return metaProject;
    }

    /// @return The effective share manager
    function ActualShareManager() constant returns (address) {
        return revisions[0].shareManager;
    }

    /// @return The effective token manager
    function ActualTokenManager() constant returns (address) {
        return revisions[0].tokenManager;
    }

// modifiers

    modifier onlyPassCommitteeRoom {if (msg.sender != revisions[0].committeeRoom  
        && revisions[0].committeeRoom != 0) throw; _;}
    
// Constructor function

    function PassDao() {
        projects.length = 1;
        revisions.length = 1;
    }
    
// Register functions

    /// @dev Function to allow the actual Committee Room upgrading the application
    /// @param _newCommitteeRoom The address of the new committee room
    /// @param _newShareManager The address of the new share manager
    /// @param _newTokenManager The address of the new token manager
    /// @return The index of the revision
    function upgrade(
        address _newCommitteeRoom, 
        address _newShareManager, 
        address _newTokenManager) onlyPassCommitteeRoom returns (uint) {
        
        uint _revisionID = revisions.length++;
        revision r = revisions[_revisionID];

        if (_newCommitteeRoom != 0) r.committeeRoom = _newCommitteeRoom; else r.committeeRoom = revisions[0].committeeRoom;
        if (_newShareManager != 0) r.shareManager = _newShareManager; else r.shareManager = revisions[0].shareManager;
        if (_newTokenManager != 0) r.tokenManager = _newTokenManager; else r.tokenManager = revisions[0].tokenManager;

        r.startDate = now;
        
        revisions[0] = r;
        
        Upgrade(_revisionID, _newCommitteeRoom, _newShareManager, _newTokenManager);
            
        return _revisionID;
    }

    /// @dev Function to set the meta project
    /// @param _projectAddress The address of the meta project
    function addMetaProject(address _projectAddress) onlyPassCommitteeRoom {

        metaProject = _projectAddress;
    }
    
    /// @dev Function to allow the committee room to add a project when ordering
    /// @param _projectAddress The address of the project
    function addProject(address _projectAddress) onlyPassCommitteeRoom {

        if (projectID[_projectAddress] == 0) {

            uint _projectID = projects.length++;
            project p = projects[_projectID];
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Initialize project with temporary data
            p.contractAddress = _projectAddress;
            p.startDate = now;
            
            // External call to notify project before finalizing registration
            // This allows the project contract to perform initialization
            if (_projectAddress.call(bytes4(keccak256("onProjectRegistered(uint256)")), _projectID)) {
                // Project acknowledged registration
            }
            
            // Finalize project registration after external call
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            projectID[_projectAddress] = _projectID;
            
            NewProject(_projectAddress);
        }
    }
    
}

pragma solidity ^0.4.8;

/*
 *
 * This file is part of Pass DAO.
 *
 * The Project smart contract is used for the management of the Pass Dao projects.
 *
*/

/// @title Project smart contract of the Pass Decentralized Autonomous Organisation
contract PassProject {

    // The Pass Dao smart contract
    PassDao public passDao;
    
    // The project name
    string public name;
    // The project description
    string public description;
    // The Hash Of the project Document
    bytes32 public hashOfTheDocument;
    // The project manager smart contract
    address projectManager;

    struct order {
        // The address of the contractor smart contract
        address contractorAddress;
        // The index of the contractor proposal
        uint contractorProposalID;
        // The amount of the order
        uint amount;
        // The date of the order
        uint orderDate;
    }
    // The orders of the Dao for this project
    order[] public orders;
    
    // The total amount of orders in wei for this project
    uint public totalAmountOfOrders;

    struct resolution {
        // The name of the resolution
        string name;
        // A description of the resolution
        string description;
        // The date of the resolution
        uint creationDate;
    }
    // Resolutions of the Dao for this project
    resolution[] public resolutions;
    
// Events

    event OrderAdded(address indexed Client, address indexed ContractorAddress, uint indexed ContractorProposalID, uint Amount, uint OrderDate);
    event ProjectDescriptionUpdated(address indexed By, string NewDescription, bytes32 NewHashOfTheDocument);
    event ResolutionAdded(address indexed Client, uint indexed ResolutionID, string Name, string Description);

// Constant functions  

    /// @return the actual committee room of the Dao   
    function Client() constant returns (address) {
        return passDao.ActualCommitteeRoom();
    }
    
    /// @return The number of orders 
    function numberOfOrders() constant returns (uint) {
        return orders.length - 1;
    }
    
    /// @return The project Manager address
    function ProjectManager() constant returns (address) {
        return projectManager;
    }

    /// @return The number of resolutions 
    function numberOfResolutions() constant returns (uint) {
        return resolutions.length - 1;
    }
    
// modifiers

    // Modifier for project manager functions 
    modifier onlyProjectManager {if (msg.sender != projectManager) throw; _;}

    // Modifier for the Dao functions 
    modifier onlyClient {if (msg.sender != Client()) throw; _;}

// Constructor function

    function PassProject(
        PassDao _passDao, 
        string _name,
        string _description,
        bytes32 _hashOfTheDocument) {

        passDao = _passDao;
        name = _name;
        description = _description;
        hashOfTheDocument = _hashOfTheDocument;
        
        orders.length = 1;
        resolutions.length = 1;
    }
    
// Internal functions

    /// @dev Internal function to register a new order
    /// @param _contractorAddress The address of the contractor smart contract
    /// @param _contractorProposalID The index of the contractor proposal
    /// @param _amount The amount in wei of the order
    /// @param _orderDate The date of the order 
    function addOrder(

        address _contractorAddress, 
        uint _contractorProposalID, 
        uint _amount, 
        uint _orderDate) internal {

        uint _orderID = orders.length++;
        order d = orders[_orderID];
        d.contractorAddress = _contractorAddress;
        d.contractorProposalID = _contractorProposalID;
        d.amount = _amount;
        d.orderDate = _orderDate;
        
        totalAmountOfOrders += _amount;
        
        OrderAdded(msg.sender, _contractorAddress, _contractorProposalID, _amount, _orderDate);
    }
    
// Setting functions

    /// @notice Function to allow cloning orders in case of upgrade
    /// @param _contractorAddress The address of the contractor smart contract
    /// @param _contractorProposalID The index of the contractor proposal
    /// @param _orderAmount The amount in wei of the order
    /// @param _lastOrderDate The unix date of the last order 
    function cloneOrder(
        address _contractorAddress, 
        uint _contractorProposalID, 
        uint _orderAmount, 
        uint _lastOrderDate) {
        
        if (projectManager != 0) throw;
        
        addOrder(_contractorAddress, _contractorProposalID, _orderAmount, _lastOrderDate);
    }
    
    /// @notice Function to set the project manager
    /// @param _projectManager The address of the project manager smart contract
    /// @return True if successful
    function setProjectManager(address _projectManager) returns (bool) {

        if (_projectManager == 0 || projectManager != 0) return;
        
        projectManager = _projectManager;
        
        return true;
    }

// Project manager functions

    /// @notice Function to allow the project manager updating the description of the project
    /// @param _projectDescription A description of the project
    /// @param _hashOfTheDocument The hash of the last document
    function updateDescription(string _projectDescription, bytes32 _hashOfTheDocument) onlyProjectManager {
        description = _projectDescription;
        hashOfTheDocument = _hashOfTheDocument;
        ProjectDescriptionUpdated(msg.sender, _projectDescription, _hashOfTheDocument);
    }

// Client functions

    /// @dev Function to allow the Dao to register a new order
    /// @param _contractorAddress The address of the contractor smart contract
    /// @param _contractorProposalID The index of the contractor proposal
    /// @param _amount The amount in wei of the order
    function newOrder(
        address _contractorAddress, 
        uint _contractorProposalID, 
        uint _amount) onlyClient {
            
        addOrder(_contractorAddress, _contractorProposalID, _amount, now);
    }
    
    /// @dev Function to allow the Dao to register a new resolution
    /// @param _name The name of the resolution
    /// @param _description The description of the resolution
    function newResolution(
        string _name, 
        string _description) onlyClient {

        uint _resolutionID = resolutions.length++;
        resolution d = resolutions[_resolutionID];
        
        d.name = _name;
        d.description = _description;
        d.creationDate = now;

        ResolutionAdded(msg.sender, _resolutionID, d.name, d.description);
    }
}

contract PassProjectCreator {
    
    event NewPassProject(PassDao indexed Dao, PassProject indexed Project, string Name, string Description, bytes32 HashOfTheDocument);

    /// @notice Function to create a new Pass project
    /// @param _passDao The Pass Dao smart contract
    /// @param _name The project name
    /// @param _description The project description (not mandatory, can be updated after by the creator)
    /// @param _hashOfTheDocument The Hash Of the project Document (not mandatory, can be updated after by the creator)
    function createProject(
        PassDao _passDao,
        string _name, 
        string _description, 
        bytes32 _hashOfTheDocument
        ) returns (PassProject) {

        PassProject _passProject = new PassProject(_passDao, _name, _description, _hashOfTheDocument);

        NewPassProject(_passDao, _passProject, _name, _description, _hashOfTheDocument);

        return _passProject;
    }
}